{{- define "dn42-autopeer.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "dn42-autopeer.selectorLabels" -}}
app.kubernetes.io/name: dn42-autopeer
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "dn42-autopeer.labels" -}}
helm.sh/chart: {{ include "dn42-autopeer.chart" . }}
{{ include "dn42-autopeer.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: dn42-router
{{- end -}}

{{- define "dn42-autopeer.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{- define "dn42-autopeer.validate" -}}
{{- if gt (int .Values.replicaCount) 1 -}}
{{- fail "replicaCount must be 1: the submission rate limits are kept in memory, per replica" -}}
{{- end -}}
{{- if not .Values.existingSecret -}}
{{- fail "existingSecret is required (cookie key, GitHub App key, client secrets)" -}}
{{- end -}}
{{- if and .Values.gitSync.enabled (not .Values.gitSync.username) -}}
{{- fail "gitSync.username is required: git.dn42.dev has no anonymous clones" -}}
{{- end -}}
{{- range $name, $_ := .Values.extraConfigFiles -}}
{{- if or (eq $name "config.yaml") (not (regexMatch "^[A-Za-z0-9._-]+$" $name)) -}}
{{- fail (printf "extraConfigFiles: %q must be a plain file name other than config.yaml" $name) -}}
{{- end -}}
{{- end -}}
{{- with .Values.config.kubernetes -}}
{{- if and .enabled (ne (default "dn42" .namespace) $.Values.peersNamespace) -}}
{{- fail "config.kubernetes.namespace must equal peersNamespace (the Role is only there)" -}}
{{- end -}}
{{- end -}}
{{- end -}}
