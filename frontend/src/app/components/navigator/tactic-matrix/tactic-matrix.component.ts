/**
 * MITRE ATT&CK Tactic Matrix Component
 *
 * Displays techniques grouped by tactic in a columnar layout
 * similar to the official MITRE ATT&CK Navigator.
 */

import { Component, Input, Output, EventEmitter, OnChanges, SimpleChanges } from '@angular/core';
import { CommonModule } from '@angular/common';
import { LayerTechnique } from '../../../services/api.service';

// MITRE ATT&CK Enterprise Tactics in canonical order
export const MITRE_TACTICS = [
  { id: 'reconnaissance', name: 'Reconnaissance', shortName: 'Recon' },
  { id: 'resource-development', name: 'Resource Development', shortName: 'Resource Dev' },
  { id: 'initial-access', name: 'Initial Access', shortName: 'Init Access' },
  { id: 'execution', name: 'Execution', shortName: 'Execution' },
  { id: 'persistence', name: 'Persistence', shortName: 'Persistence' },
  { id: 'privilege-escalation', name: 'Privilege Escalation', shortName: 'Priv Esc' },
  { id: 'defense-evasion', name: 'Defense Evasion', shortName: 'Def Evasion' },
  { id: 'credential-access', name: 'Credential Access', shortName: 'Cred Access' },
  { id: 'discovery', name: 'Discovery', shortName: 'Discovery' },
  { id: 'lateral-movement', name: 'Lateral Movement', shortName: 'Lat Movement' },
  { id: 'collection', name: 'Collection', shortName: 'Collection' },
  { id: 'command-and-control', name: 'Command and Control', shortName: 'C2' },
  { id: 'exfiltration', name: 'Exfiltration', shortName: 'Exfil' },
  { id: 'impact', name: 'Impact', shortName: 'Impact' }
];

// Technique ID to Tactic mapping (primary tactic for each technique)
// Note: Some techniques appear in multiple tactics in MITRE ATT&CK
// This mapping uses the most commonly associated tactic
// In production, this would come from the MITRE ATT&CK STIX data
const TECHNIQUE_TACTIC_MAP: Record<string, string> = {
  // Reconnaissance
  'T1595': 'reconnaissance', 'T1592': 'reconnaissance', 'T1589': 'reconnaissance',
  'T1590': 'reconnaissance', 'T1591': 'reconnaissance', 'T1598': 'reconnaissance',
  // Resource Development
  'T1583': 'resource-development', 'T1584': 'resource-development', 'T1587': 'resource-development',
  'T1588': 'resource-development', 'T1608': 'resource-development',
  // Initial Access
  'T1189': 'initial-access', 'T1190': 'initial-access', 'T1133': 'initial-access',
  'T1200': 'initial-access', 'T1566': 'initial-access', 'T1091': 'initial-access',
  'T1195': 'initial-access', 'T1199': 'initial-access', 'T1078': 'initial-access',
  // Execution
  'T1059': 'execution', 'T1203': 'execution', 'T1559': 'execution',
  'T1106': 'execution', 'T1053': 'execution', 'T1129': 'execution',
  'T1072': 'execution', 'T1569': 'execution', 'T1204': 'execution',
  'T1047': 'execution',
  // Persistence
  'T1098': 'persistence', 'T1197': 'persistence', 'T1547': 'persistence',
  'T1037': 'persistence', 'T1176': 'persistence', 'T1554': 'persistence',
  'T1136': 'persistence', 'T1543': 'persistence', 'T1546': 'persistence',
  'T1574': 'persistence', 'T1525': 'persistence', 'T1137': 'persistence',
  'T1505': 'persistence', 'T1205': 'persistence',
  // Privilege Escalation
  'T1548': 'privilege-escalation', 'T1134': 'privilege-escalation',
  'T1484': 'privilege-escalation', 'T1068': 'privilege-escalation',
  'T1055': 'privilege-escalation',
  // Defense Evasion
  'T1140': 'defense-evasion', 'T1006': 'defense-evasion',
  'T1480': 'defense-evasion', 'T1211': 'defense-evasion', 'T1222': 'defense-evasion',
  'T1564': 'defense-evasion', 'T1562': 'defense-evasion',
  'T1070': 'defense-evasion', 'T1202': 'defense-evasion', 'T1036': 'defense-evasion',
  'T1556': 'defense-evasion', 'T1578': 'defense-evasion', 'T1112': 'defense-evasion',
  'T1601': 'defense-evasion', 'T1599': 'defense-evasion', 'T1027': 'defense-evasion',
  'T1542': 'defense-evasion', 'T1207': 'defense-evasion',
  'T1014': 'defense-evasion', 'T1218': 'defense-evasion', 'T1216': 'defense-evasion',
  'T1553': 'defense-evasion', 'T1221': 'defense-evasion',
  'T1127': 'defense-evasion', 'T1535': 'defense-evasion', 'T1550': 'defense-evasion',
  'T1497': 'defense-evasion', 'T1600': 'defense-evasion', 'T1220': 'defense-evasion',
  // Credential Access
  'T1557': 'credential-access', 'T1110': 'credential-access', 'T1555': 'credential-access',
  'T1212': 'credential-access', 'T1187': 'credential-access', 'T1606': 'credential-access',
  'T1056': 'credential-access', 'T1040': 'credential-access',
  'T1003': 'credential-access', 'T1528': 'credential-access', 'T1558': 'credential-access',
  'T1539': 'credential-access', 'T1111': 'credential-access', 'T1552': 'credential-access',
  // Discovery
  'T1087': 'discovery', 'T1010': 'discovery', 'T1217': 'discovery',
  'T1580': 'discovery', 'T1538': 'discovery', 'T1526': 'discovery',
  'T1482': 'discovery', 'T1083': 'discovery', 'T1615': 'discovery',
  'T1046': 'discovery', 'T1135': 'discovery',
  'T1201': 'discovery', 'T1120': 'discovery', 'T1069': 'discovery',
  'T1057': 'discovery', 'T1012': 'discovery', 'T1018': 'discovery',
  'T1518': 'discovery', 'T1082': 'discovery', 'T1614': 'discovery',
  'T1016': 'discovery', 'T1049': 'discovery', 'T1033': 'discovery',
  'T1007': 'discovery', 'T1124': 'discovery',
  // Lateral Movement
  'T1210': 'lateral-movement', 'T1534': 'lateral-movement', 'T1570': 'lateral-movement',
  'T1563': 'lateral-movement', 'T1021': 'lateral-movement',
  'T1080': 'lateral-movement',
  // Collection
  'T1560': 'collection', 'T1123': 'collection', 'T1119': 'collection',
  'T1115': 'collection', 'T1530': 'collection', 'T1602': 'collection',
  'T1213': 'collection', 'T1005': 'collection', 'T1039': 'collection',
  'T1025': 'collection', 'T1074': 'collection', 'T1114': 'collection',
  'T1185': 'collection', 'T1113': 'collection', 'T1125': 'collection',
  // Command and Control
  'T1071': 'command-and-control', 'T1092': 'command-and-control', 'T1132': 'command-and-control',
  'T1001': 'command-and-control', 'T1568': 'command-and-control', 'T1573': 'command-and-control',
  'T1008': 'command-and-control', 'T1105': 'command-and-control', 'T1104': 'command-and-control',
  'T1095': 'command-and-control', 'T1571': 'command-and-control', 'T1572': 'command-and-control',
  'T1090': 'command-and-control', 'T1219': 'command-and-control', 'T1102': 'command-and-control',
  // Exfiltration
  'T1020': 'exfiltration', 'T1030': 'exfiltration', 'T1048': 'exfiltration',
  'T1041': 'exfiltration', 'T1011': 'exfiltration', 'T1052': 'exfiltration',
  'T1567': 'exfiltration', 'T1029': 'exfiltration', 'T1537': 'exfiltration',
  // Impact
  'T1531': 'impact', 'T1485': 'impact', 'T1486': 'impact',
  'T1565': 'impact', 'T1491': 'impact', 'T1561': 'impact',
  'T1499': 'impact', 'T1495': 'impact', 'T1490': 'impact',
  'T1498': 'impact', 'T1496': 'impact', 'T1489': 'impact',
  'T1529': 'impact'
};

export interface TechniqueWithTactic extends LayerTechnique {
  tactic: string;
  tacticName: string;
}

export interface TacticColumn {
  id: string;
  name: string;
  shortName: string;
  techniques: TechniqueWithTactic[];
}

@Component({
  selector: 'app-tactic-matrix',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="tactic-matrix">
      <!-- Tactic Headers -->
      <div class="tactic-headers">
        <div
          *ngFor="let tactic of tacticColumns"
          class="tactic-header"
          [class.has-techniques]="tactic.techniques.length > 0"
        >
          <span class="tactic-name">{{ tactic.shortName }}</span>
          <span class="technique-count" *ngIf="tactic.techniques.length > 0">
            {{ tactic.techniques.length }}
          </span>
        </div>
      </div>

      <!-- Technique Columns -->
      <div class="tactic-columns">
        <div
          *ngFor="let tactic of tacticColumns"
          class="tactic-column"
          [class.empty]="tactic.techniques.length === 0"
        >
          <div
            *ngFor="let technique of tactic.techniques"
            class="technique-cell"
            [class.critical]="technique.from_intel && technique.from_vuln"
            [class.intel]="technique.from_intel && !technique.from_vuln"
            [class.vuln]="!technique.from_intel && technique.from_vuln"
            [class.selected]="technique.technique_id === selectedTechniqueId"
            [style.--confidence]="technique.confidence"
            (click)="selectTechnique(technique)"
            [title]="getTechniqueTooltip(technique)"
          >
            <span class="technique-id">{{ technique.technique_id }}</span>
            <div class="confidence-bar" [style.width.%]="technique.confidence * 100"></div>
          </div>

          <!-- Empty column placeholder -->
          <div *ngIf="tactic.techniques.length === 0" class="empty-column">
            <span class="empty-text">—</span>
          </div>
        </div>
      </div>

      <!-- Legend -->
      <div class="matrix-legend">
        <div class="legend-item">
          <span class="legend-color critical"></span>
          <span class="legend-label">Critical (Intel + Vuln)</span>
        </div>
        <div class="legend-item">
          <span class="legend-color intel"></span>
          <span class="legend-label">Intel Only</span>
        </div>
        <div class="legend-item">
          <span class="legend-color vuln"></span>
          <span class="legend-label">Vuln Only</span>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .tactic-matrix {
      display: flex;
      flex-direction: column;
      gap: var(--spacing-md);
      overflow-x: auto;
      padding: var(--spacing-md);
    }

    /* Tactic Headers */
    .tactic-headers {
      display: flex;
      gap: 2px;
      min-width: fit-content;
    }

    .tactic-header {
      flex: 1;
      min-width: 90px;
      max-width: 120px;
      padding: var(--spacing-sm) var(--spacing-xs);
      background: var(--color-surface-elevated);
      border-radius: var(--radius-sm) var(--radius-sm) 0 0;
      text-align: center;
      border-bottom: 2px solid var(--color-border);
      transition: all 0.2s ease;
    }

    .tactic-header.has-techniques {
      border-bottom-color: var(--color-accent);
    }

    .tactic-name {
      display: block;
      font-size: 0.7rem;
      font-weight: 600;
      color: var(--color-text-secondary);
      text-transform: uppercase;
      letter-spacing: 0.03em;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .technique-count {
      display: inline-block;
      margin-top: 2px;
      padding: 1px 6px;
      background: var(--color-accent);
      color: white;
      font-size: 0.65rem;
      font-weight: 600;
      border-radius: 10px;
    }

    /* Technique Columns */
    .tactic-columns {
      display: flex;
      gap: 2px;
      min-width: fit-content;
    }

    .tactic-column {
      flex: 1;
      min-width: 90px;
      max-width: 120px;
      display: flex;
      flex-direction: column;
      gap: 2px;
      background: var(--color-surface);
      border-radius: 0 0 var(--radius-sm) var(--radius-sm);
      padding: 2px;
      min-height: 200px;
    }

    .tactic-column.empty {
      opacity: 0.5;
    }

    /* Technique Cells */
    .technique-cell {
      position: relative;
      padding: var(--spacing-xs) var(--spacing-sm);
      border-radius: var(--radius-sm);
      cursor: pointer;
      transition: all 0.2s ease;
      overflow: hidden;
    }

    .technique-cell.critical {
      background: rgba(239, 68, 68, 0.2);
      border-left: 3px solid var(--color-red);
    }

    .technique-cell.intel {
      background: rgba(245, 158, 11, 0.2);
      border-left: 3px solid var(--color-yellow);
    }

    .technique-cell.vuln {
      background: rgba(59, 130, 246, 0.2);
      border-left: 3px solid var(--color-blue);
    }

    .technique-cell:hover {
      transform: scale(1.02);
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
      z-index: 1;
    }

    .technique-cell.selected {
      outline: 2px solid var(--color-accent);
      outline-offset: 1px;
    }

    .technique-cell.critical:hover {
      background: rgba(239, 68, 68, 0.35);
    }

    .technique-cell.intel:hover {
      background: rgba(245, 158, 11, 0.35);
    }

    .technique-cell.vuln:hover {
      background: rgba(59, 130, 246, 0.35);
    }

    .technique-id {
      display: block;
      font-family: var(--font-family-mono);
      font-size: 0.7rem;
      font-weight: 600;
      color: var(--color-text-primary);
    }

    .confidence-bar {
      position: absolute;
      bottom: 0;
      left: 0;
      height: 2px;
      background: var(--color-accent);
      opacity: 0.6;
      transition: width 0.3s ease;
    }

    /* Empty Column */
    .empty-column {
      flex: 1;
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--color-text-tertiary);
    }

    .empty-text {
      font-size: 1.5rem;
      opacity: 0.3;
    }

    /* Legend */
    .matrix-legend {
      display: flex;
      gap: var(--spacing-lg);
      justify-content: center;
      padding-top: var(--spacing-md);
      border-top: 1px solid var(--color-border);
    }

    .legend-item {
      display: flex;
      align-items: center;
      gap: var(--spacing-xs);
    }

    .legend-color {
      width: 16px;
      height: 16px;
      border-radius: var(--radius-sm);
    }

    .legend-color.critical {
      background: rgba(239, 68, 68, 0.3);
      border-left: 3px solid var(--color-red);
    }

    .legend-color.intel {
      background: rgba(245, 158, 11, 0.3);
      border-left: 3px solid var(--color-yellow);
    }

    .legend-color.vuln {
      background: rgba(59, 130, 246, 0.3);
      border-left: 3px solid var(--color-blue);
    }

    .legend-label {
      font-size: 0.75rem;
      color: var(--color-text-secondary);
    }

    /* Critical technique pulse animation */
    .technique-cell.critical {
      animation: pulseCritical 2s ease-in-out infinite;
    }

    @keyframes pulseCritical {
      0%, 100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.4); }
      50% { box-shadow: 0 0 0 4px rgba(239, 68, 68, 0); }
    }
  `]
})
export class TacticMatrixComponent implements OnChanges {
  @Input() techniques: LayerTechnique[] = [];
  @Input() selectedTechniqueId: string | null = null;
  @Output() techniqueSelected = new EventEmitter<string>();

  tacticColumns: TacticColumn[] = [];

  ngOnChanges(changes: SimpleChanges): void {
    if (changes['techniques']) {
      this.buildTacticColumns();
    }
  }

  private buildTacticColumns(): void {
    // Initialize columns for all tactics
    this.tacticColumns = MITRE_TACTICS.map(tactic => ({
      ...tactic,
      techniques: []
    }));

    // Group techniques by tactic
    for (const technique of this.techniques) {
      const tacticId = this.getTacticForTechnique(technique.technique_id);
      const column = this.tacticColumns.find(c => c.id === tacticId);

      if (column) {
        column.techniques.push({
          ...technique,
          tactic: tacticId,
          tacticName: column.name
        });
      }
    }

    // Sort techniques within each column by confidence (highest first)
    for (const column of this.tacticColumns) {
      column.techniques.sort((a, b) => b.confidence - a.confidence);
    }
  }

  private getTacticForTechnique(techniqueId: string): string {
    // Extract base technique ID (e.g., T1059.001 -> T1059)
    const baseId = techniqueId.split('.')[0];

    // Look up in mapping
    const tactic = TECHNIQUE_TACTIC_MAP[baseId];

    // Default to 'execution' if unknown (most common fallback)
    return tactic || 'execution';
  }

  selectTechnique(technique: TechniqueWithTactic): void {
    this.techniqueSelected.emit(technique.technique_id);
  }

  getTechniqueTooltip(technique: TechniqueWithTactic): string {
    const type = technique.from_intel && technique.from_vuln ? 'Critical'
      : technique.from_intel ? 'Intel'
      : 'Vulnerability';
    return `${technique.technique_id} | ${type} | Confidence: ${(technique.confidence * 100).toFixed(0)}%`;
  }
}
