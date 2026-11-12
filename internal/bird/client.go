package bird

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Reply is one complete reply from the BIRD control socket.
type Reply struct {
	Code  int    // code of the final line
	Lines []Line // every line, continuation lines carry the code before them
}

// Line is one reply line.
type Line struct {
	Code int
	Text string
}

// Err returns an error for 8xxx (runtime) and 9xxx (parse) replies.
func (r *Reply) Err() error {
	if r.Code >= 8000 {
		var msgs []string
		for _, l := range r.Lines {
			if l.Code >= 8000 {
				msgs = append(msgs, l.Text)
			}
		}
		return &ReplyError{Code: r.Code, Message: strings.Join(msgs, "; ")}
	}
	return nil
}

// Text joins all lines.
func (r *Reply) Text() string {
	var s []string
	for _, l := range r.Lines {
		s = append(s, l.Text)
	}
	return strings.Join(s, "\n")
}

// ReplyError is an error reply from BIRD.
type ReplyError struct {
	Code    int
	Message string
}

func (e *ReplyError) Error() string { return fmt.Sprintf("bird: %04d %s", e.Code, e.Message) }

// Client talks to BIRD's control socket directly, one connection per
// command, so no birdc binary is needed.
type Client struct {
	Socket  string
	Timeout time.Duration
}

// Command sends one command and reads the full reply.
func (c *Client) Command(ctx context.Context, cmd string) (*Reply, error) {
	if strings.ContainsAny(cmd, "\r\n") {
		return nil, fmt.Errorf("bird: command contains a newline")
	}
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return nil, fmt.Errorf("bird: %w", err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	r := bufio.NewReader(conn)
	// Greeting: "0001 BIRD 2.x ready."
	hello, err := readReply(r)
	if err != nil {
		return nil, fmt.Errorf("bird: greeting: %w", err)
	}
	if hello.Code != 1 {
		return nil, fmt.Errorf("bird: unexpected greeting %q", hello.Text())
	}
	if _, err := conn.Write([]byte(cmd + "\n")); err != nil {
		return nil, fmt.Errorf("bird: %w", err)
	}
	rep, err := readReply(r)
	if err != nil {
		return nil, fmt.Errorf("bird: %s: %w", cmd, err)
	}
	return rep, nil
}

// readReply reads lines until a final line ("NNNN " with a space).
// "NNNN-text" continues with a new code, " text" continues the last code.
// Async lines starting with '+' are skipped.
func readReply(r *bufio.Reader) (*Reply, error) {
	rep := &Reply{}
	last := 0
	for {
		s, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		s = strings.TrimRight(s, "\r\n")
		switch {
		case strings.HasPrefix(s, "+"):
			continue
		case strings.HasPrefix(s, " "):
			rep.Lines = append(rep.Lines, Line{Code: last, Text: s[1:]})
			continue
		case len(s) >= 5 && (s[4] == ' ' || s[4] == '-'):
			code, err := strconv.Atoi(s[:4])
			if err != nil {
				return nil, fmt.Errorf("malformed line %q", s)
			}
			last = code
			rep.Lines = append(rep.Lines, Line{Code: code, Text: s[5:]})
			if s[4] == ' ' {
				rep.Code = code
				return rep, nil
			}
		case len(s) == 4:
			code, err := strconv.Atoi(s)
			if err != nil {
				return nil, fmt.Errorf("malformed line %q", s)
			}
			rep.Code = code
			return rep, nil
		default:
			return nil, fmt.Errorf("malformed line %q", s)
		}
	}
}

// ConfigureCheck runs "configure check" on BIRD's own config file.
func (c *Client) ConfigureCheck(ctx context.Context) error {
	rep, err := c.Command(ctx, "configure check")
	if err != nil {
		return err
	}
	if err := rep.Err(); err != nil {
		return err
	}
	if rep.Code != 20 { // 0020 Configuration OK
		return fmt.Errorf("bird: configure check: unexpected reply %04d %s", rep.Code, rep.Text())
	}
	return nil
}

// Configure reloads BIRD's config.
func (c *Client) Configure(ctx context.Context) error {
	rep, err := c.Command(ctx, "configure")
	if err != nil {
		return err
	}
	if err := rep.Err(); err != nil {
		return err
	}
	switch rep.Code {
	case 3, 4, 5, 18, 19: // reconfigured, in progress, queued, confirmed, nothing to do
		return nil
	}
	return fmt.Errorf("bird: configure: unexpected reply %04d %s", rep.Code, rep.Text())
}

// ProtocolStatus is what "show protocols all" reports for one protocol.
type ProtocolStatus struct {
	Name           string
	Proto          string
	State          string // up, down, start, ...
	BGPState       string // Established, Active, ... ("" for non-BGP)
	RoutesImported int64
	HasRoutes      bool
}

// ShowProtocols returns every protocol by name.
func (c *Client) ShowProtocols(ctx context.Context) (map[string]ProtocolStatus, error) {
	rep, err := c.Command(ctx, "show protocols all")
	if err != nil {
		return nil, err
	}
	if err := rep.Err(); err != nil {
		return nil, err
	}
	return ParseProtocols(rep), nil
}

var bgpStates = map[string]bool{
	"Idle": true, "Connect": true, "Active": true, "OpenSent": true,
	"OpenConfirm": true, "Established": true, "Close": true, "Down": true,
}

// ParseProtocols parses a "show protocols all" reply: 1002 lines are the
// protocol table rows, 1006 lines the details under the last row.
func ParseProtocols(rep *Reply) map[string]ProtocolStatus {
	out := map[string]ProtocolStatus{}
	var cur *ProtocolStatus
	flush := func() {
		if cur != nil {
			out[cur.Name] = *cur
		}
	}
	for _, l := range rep.Lines {
		switch l.Code {
		case 1002:
			f := strings.Fields(l.Text)
			if len(f) < 4 {
				continue
			}
			flush()
			cur = &ProtocolStatus{Name: f[0], Proto: f[1], State: f[3]}
			if cur.Proto == "BGP" {
				for _, w := range f[4:] {
					if bgpStates[w] {
						cur.BGPState = w
						break
					}
				}
			}
		case 1006:
			if cur == nil {
				continue
			}
			t := strings.TrimSpace(l.Text)
			if rest, ok := strings.CutPrefix(t, "Routes:"); ok {
				for _, part := range strings.Split(rest, ",") {
					f := strings.Fields(part)
					if len(f) == 2 && f[1] == "imported" {
						if n, err := strconv.ParseInt(f[0], 10, 64); err == nil {
							cur.RoutesImported += n
							cur.HasRoutes = true
						}
					}
				}
			}
			if rest, ok := strings.CutPrefix(t, "BGP state:"); ok && cur.Proto == "BGP" {
				if s := strings.TrimSpace(rest); bgpStates[s] {
					cur.BGPState = s
				}
			}
		}
	}
	flush()
	return out
}
