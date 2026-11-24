{{/*
Fixed names: the operator finds its Lease, pods and the endpoint Service by
them, and one release per namespace is the only supported layout.
*/}}

{{- define "dn42-operator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "dn42-operator.labels" -}}
helm.sh/chart: {{ include "dn42-operator.chart" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: dn42-router
{{- end -}}

{{- define "dn42-operator.image" -}}
{{- if .Values.operator.image.digest -}}
{{- printf "%s@%s" .Values.operator.image.repository .Values.operator.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.operator.image.repository (default .Chart.AppVersion .Values.operator.image.tag) -}}
{{- end -}}
{{- end -}}

{{- define "dn42-operator.birdImage" -}}
{{- $i := .Values.bird.image -}}
{{- if $i.digest -}}
{{- printf "%s:%s@%s" $i.repository $i.tag $i.digest -}}
{{- else -}}
{{- printf "%s:%s" $i.repository $i.tag -}}
{{- end -}}
{{- end -}}

{{- define "dn42-operator.birdConfigMap" -}}
{{- required "bird.config.configMapName is required" .Values.bird.config.configMapName -}}
{{- end -}}

{{/* Volumes both DaemonSets mount. */}}
{{- define "dn42-operator.volumes" -}}
- name: conf
  configMap:
    name: {{ include "dn42-operator.birdConfigMap" . }}
- name: live
  hostPath: {path: {{ .Values.hostPaths.configDir }}, type: DirectoryOrCreate}
- name: peers
  hostPath: {path: {{ .Values.hostPaths.peersDir }}, type: DirectoryOrCreate}
- name: run
  hostPath: {path: {{ .Values.hostPaths.socketDir }}, type: DirectoryOrCreate}
{{- end -}}

{{- define "dn42-operator.validate" -}}
{{- if and .Values.bird.config.create (not .Values.bird.config.content) -}}
{{- fail "bird.config.create needs bird.config.content (the bird.conf)" -}}
{{- end -}}
{{- if and .Values.bird.config.content (not .Values.bird.config.create) -}}
{{- fail "bird.config.content is set but create is false; set create: true, or drop content and provide the ConfigMap" -}}
{{- end -}}
{{- if not .Values.bird.image.tag -}}
{{- fail "bird.image.tag is required (the BIRD version)" -}}
{{- end -}}
{{- if not .Values.operator.keySecret -}}
{{- fail "operator.keySecret is required" -}}
{{- end -}}
{{- end -}}
