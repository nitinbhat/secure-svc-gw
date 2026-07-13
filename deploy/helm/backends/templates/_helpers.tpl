{{- define "be.labels" -}}
app.kubernetes.io/name: secure-svc-backends
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: secure-svc-gw
app.kubernetes.io/component: backend
{{- end -}}
