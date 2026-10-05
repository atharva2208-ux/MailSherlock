// The API contract is defined once, in the server's domain model.
import type { ThreatIntelResult } from '@shared/analysis';

export type * from '@shared/analysis';

export interface SampleEmail {
  name: string;
  label: 'phishing' | 'legitimate';
  title: string;
}

export interface CandidateRow {
  candidate: string;
  description: string;
  explainable: boolean;
  eligible?: boolean;
  prior_violations?: { feature: string; weight: number }[];
  recall_at_target_fpr: number;
  train_seconds: number;
  validation: ModelMetrics;
}

export interface ModelMetrics {
  samples: number;
  phishing: number;
  legitimate: number;
  threshold: number;
  precision: number | null;
  recall: number | null;
  f1: number | null;
  accuracy: number | null;
  false_positive_rate: number | null;
  false_negative_rate: number | null;
  roc_auc: number | null;
  pr_auc: number | null;
  confusion_matrix: { tp: number; fp: number; tn: number; fn: number };
}

export interface ModelInfoResponse {
  available: boolean;
  source?: 'service' | 'artifacts';
  serviceUp: boolean;
  message?: string;
  metadata?: {
    model_name: string;
    model_version: string;
    dataset_version: string;
    feature_version: string;
    candidate: string;
    description: string;
    training_date: string;
    training_samples: number;
    training_phishing: number;
    training_legitimate: number;
    validation_samples: number;
    threshold: number;
    threshold_policy: string;
    dataset_sources: {
      name: string;
      label: string;
      url: string;
      license: string;
      description: string;
    }[];
    selection: { criterion: string; candidates: CandidateRow[] };
    environment: Record<string, string>;
  };
  metrics?: {
    test: ModelMetrics & { at_threshold_0_5: ModelMetrics };
    validation?: ModelMetrics;
    challenge: ModelMetrics & {
      predictions: {
        id: string;
        subject: string;
        label: string;
        probability: number;
        predicted: string;
      }[];
    };
    feature_weights: {
      phishing: { kind: string; feature: string; weight: number }[];
      legitimate: { kind: string; feature: string; weight: number }[];
    } | null;
  };
}

export interface IntelResponse {
  indicator: string;
  kind: 'domain' | 'ip';
  local: {
    domain: string;
    registrableDomain: string;
    unicodeDomain: string;
    publicSuffix: string;
    officialBrand: string | null;
    freeMailProvider: boolean;
    urlShortener: boolean;
    suspiciousTld: boolean;
    lookalike: { brand: string; technique: string; confidence: number; detail: string } | null;
    homoglyph: { scripts: string[]; mixedScript: boolean; skeleton: string } | null;
  } | null;
  external: ThreatIntelResult[];
}
