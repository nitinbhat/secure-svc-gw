{{- define "gw.labels" -}}
app.kubernetes.io/name: secure-svc-gw
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: secure-svc-gw
{{- end -}}

{{- define "gw.gatewayLabels" -}}
{{ include "gw.labels" . }}
app.kubernetes.io/component: gateway
{{- end -}}
