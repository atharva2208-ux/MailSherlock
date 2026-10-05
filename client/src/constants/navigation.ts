import {
  Activity,
  BrainCircuit,
  FileText,
  FolderSearch,
  Globe2,
  LayoutDashboard,
  ScanSearch,
  Settings,
} from 'lucide-react';

export const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/analyze', label: 'Analyze', icon: ScanSearch },
  { to: '/investigations', label: 'Investigations', icon: FolderSearch },
  { to: '/intel', label: 'Threat intel', icon: Globe2 },
  { to: '/reports', label: 'Reports', icon: FileText },
  { to: '/model', label: 'Model', icon: BrainCircuit },
  { to: '/settings', label: 'Settings', icon: Settings },
] as const;

export const SYSTEM_ICON = Activity;
