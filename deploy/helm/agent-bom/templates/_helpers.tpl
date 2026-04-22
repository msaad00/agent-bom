{{/*
Expand the name of the chart.
*/}}
{{- define "agent-bom.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "agent-bom.labels" -}}
app.kubernetes.io/name: {{ include "agent-bom.name" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end }}

{{/*
Service account name.
*/}}
{{- define "agent-bom.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "agent-bom.name" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Gateway service account name.
*/}}
{{- define "agent-bom.gatewayServiceAccountName" -}}
{{- if .Values.gateway.serviceAccount.create }}
{{- default (printf "%s-gateway" (include "agent-bom.name" .)) .Values.gateway.serviceAccount.name }}
{{- else }}
{{- default (include "agent-bom.serviceAccountName" .) .Values.gateway.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Sidecar injector full name.
*/}}
{{- define "agent-bom.sidecarInjectorName" -}}
{{- printf "%s-sidecar-injector" (include "agent-bom.name" .) -}}
{{- end }}

{{/*
Scanner service account name.
*/}}
{{- define "agent-bom.scannerServiceAccountName" -}}
{{- if .Values.scanner.serviceAccount.create }}
{{- default (printf "%s-scanner" (include "agent-bom.name" .)) .Values.scanner.serviceAccount.name }}
{{- else }}
{{- default (include "agent-bom.serviceAccountName" .) .Values.scanner.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Backup service account name.
*/}}
{{- define "agent-bom.controlPlaneBackupServiceAccountName" -}}
{{- if .Values.controlPlane.backup.serviceAccountName }}
{{- .Values.controlPlane.backup.serviceAccountName }}
{{- else if .Values.controlPlane.backup.serviceAccount.create }}
{{- default (printf "%s-backup" (include "agent-bom.name" .)) .Values.controlPlane.backup.serviceAccount.name }}
{{- else }}
{{- include "agent-bom.serviceAccountName" . }}
{{- end }}
{{- end }}

{{/*
Control-plane affinity helper. If the operator provides a full affinity block,
use it verbatim. Otherwise, optionally emit preferred pod anti-affinity so API
and UI replicas avoid co-location on the same node.
*/}}
{{- define "agent-bom.controlPlaneAffinity" -}}
{{- if .Values.affinity }}
affinity:
  {{- toYaml .Values.affinity | nindent 2 }}
{{- else if .Values.controlPlane.podAntiAffinity.enabled }}
affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          topologyKey: {{ .Values.controlPlane.podAntiAffinity.topologyKey }}
          labelSelector:
            matchLabels:
              app.kubernetes.io/name: {{ include "agent-bom.name" . }}
              app.kubernetes.io/component: {{ .component }}
{{- end }}
{{- end }}

{{/*
Resolved PriorityClass name for control-plane workloads.
*/}}
{{- define "agent-bom.controlPlanePriorityClassName" -}}
{{- if .Values.controlPlane.priorityClass.create -}}
{{- default (printf "%s-control-plane" (include "agent-bom.name" .)) .Values.controlPlane.priorityClass.name -}}
{{- else -}}
{{- .Values.controlPlane.priorityClass.name -}}
{{- end -}}
{{- end }}

{{/*
Control-plane topology spread constraints.
*/}}
{{- define "agent-bom.controlPlaneTopologySpreadConstraints" -}}
{{- if .Values.topologySpread.enabled }}
topologySpreadConstraints:
  {{- if .Values.topologySpread.zone.enabled }}
  - maxSkew: 1
    topologyKey: {{ .Values.topologySpread.zone.topologyKey }}
    whenUnsatisfiable: {{ .Values.topologySpread.whenUnsatisfiable }}
    labelSelector:
      matchLabels:
        app.kubernetes.io/name: {{ include "agent-bom.name" . }}
        app.kubernetes.io/component: {{ .component }}
  {{- end }}
  {{- if .Values.topologySpread.node.enabled }}
  - maxSkew: 1
    topologyKey: {{ .Values.topologySpread.node.topologyKey }}
    whenUnsatisfiable: {{ .Values.topologySpread.whenUnsatisfiable }}
    labelSelector:
      matchLabels:
        app.kubernetes.io/name: {{ include "agent-bom.name" . }}
        app.kubernetes.io/component: {{ .component }}
  {{- end }}
{{- end }}
{{- end }}
