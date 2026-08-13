import http from 'k6/http';
import { check } from 'k6';

const baseUrl = (__ENV.TREETOP_K6_BASE_URL || 'http://127.0.0.1:9999').replace(/\/$/, '');
const workload = __ENV.TREETOP_K6_WORKLOAD || 'authorize_labeled';
const mode = __ENV.TREETOP_K6_MODE || 'iterations';
const vus = positiveInteger('TREETOP_K6_VUS', 1);
const iterations = positiveInteger('TREETOP_K6_ITERATIONS', 5000);
const duration = __ENV.TREETOP_K6_DURATION || '30s';
const maxDuration = __ENV.TREETOP_K6_MAX_DURATION || '10m';
const rate = positiveInteger('TREETOP_K6_RATE', 1000);
const maxVus = positiveInteger('TREETOP_K6_MAX_VUS', Math.max(vus, 100));
const output = __ENV.TREETOP_K6_OUTPUT || 'performance-results/k6.json';

const supportedWorkloads = [
  'livez',
  'policies',
  'authorize_simple',
  'authorize_labeled',
  'authorize_batch_8',
  'authorize_batch_128',
];

if (![...supportedWorkloads, 'mixed'].includes(workload)) {
  throw new Error(`unsupported TREETOP_K6_WORKLOAD: ${workload}`);
}

function positiveInteger(name, defaultValue) {
  const raw = __ENV[name];
  if (raw === undefined) {
    return defaultValue;
  }
  const value = Number(raw);
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return value;
}

function scenario() {
  switch (mode) {
    case 'iterations':
      return {
        executor: 'shared-iterations',
        vus,
        iterations,
        maxDuration,
      };
    case 'duration':
      return {
        executor: 'constant-vus',
        vus,
        duration,
      };
    case 'rate':
      return {
        executor: 'constant-arrival-rate',
        rate,
        timeUnit: '1s',
        duration,
        preAllocatedVUs: vus,
        maxVUs,
      };
    default:
      throw new Error(`unsupported TREETOP_K6_MODE: ${mode}`);
  }
}

export const options = {
  discardResponseBodies: true,
  summaryTimeUnit: 'ms',
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  scenarios: {
    treetop: scenario(),
  },
  thresholds: {
    checks: ['rate==1'],
  },
};

function principal(id) {
  return {
    User: {
      id,
      namespace: [],
      groups: [],
    },
  };
}

function action(id) {
  return {
    id,
    namespace: [],
  };
}

function simpleRequest() {
  return {
    principal: principal('alice'),
    action: action('view'),
    resource: {
      kind: 'Photo',
      id: 'VacationPhoto94.jpg',
      attrs: {},
    },
  };
}

function labeledRequest() {
  return {
    principal: principal('alice'),
    action: action('create_host'),
    resource: {
      kind: 'Host',
      id: 'web-01.example.com',
      attrs: {
        name: {
          type: 'String',
          value: 'web-01.example.com',
        },
      },
    },
  };
}

function authorizationBody(size, labeled) {
  const requests = [];
  for (let index = 0; index < size; index += 1) {
    requests.push(labeled ? labeledRequest() : simpleRequest());
  }
  return JSON.stringify({ requests });
}

const requestBodies = {
  authorize_simple: authorizationBody(1, false),
  authorize_labeled: authorizationBody(1, true),
  authorize_batch_8: authorizationBody(8, true),
  authorize_batch_128: authorizationBody(128, true),
};

function execute(selectedWorkload) {
  let response;
  if (selectedWorkload === 'livez') {
    response = http.get(`${baseUrl}/livez`, { tags: { name: selectedWorkload } });
  } else if (selectedWorkload === 'policies') {
    response = http.get(`${baseUrl}/api/v1/policies`, { tags: { name: selectedWorkload } });
  } else {
    response = http.post(`${baseUrl}/api/v1/authorize`, requestBodies[selectedWorkload], {
      headers: { 'Content-Type': 'application/json' },
      tags: { name: selectedWorkload },
    });
  }

  check(response, {
    [`${selectedWorkload} returned 2xx`]: (candidate) => candidate.status >= 200 && candidate.status < 300,
  });
}

export default function () {
  const selectedWorkload = workload === 'mixed'
    ? supportedWorkloads[__ITER % supportedWorkloads.length]
    : workload;
  execute(selectedWorkload);
}

function optionalEnvironment(name) {
  return __ENV[name] || 'unknown';
}

function consoleSummary(data) {
  const requests = data.metrics.http_reqs && data.metrics.http_reqs.values;
  const durationMetric = data.metrics.http_req_duration && data.metrics.http_req_duration.values;
  const dropped = data.metrics.dropped_iterations && data.metrics.dropped_iterations.values;
  const lines = [
    '',
    `k6 workload: ${workload}; mode: ${mode}; VUs: ${vus}`,
    `REST ${optionalEnvironment('TREETOP_K6_REST_VERSION')} (${optionalEnvironment('TREETOP_K6_REST_SHA')})`,
    `Core ${optionalEnvironment('TREETOP_K6_CORE_VERSION')} (${optionalEnvironment('TREETOP_K6_CORE_SHA')})`,
  ];
  if (requests) {
    lines.push(`requests: ${requests.count}; requests/s: ${requests.rate.toFixed(1)}`);
  }
  if (durationMetric) {
    lines.push(
      `HTTP mean/p95/p99: ${durationMetric.avg.toFixed(1)}/${durationMetric['p(95)'].toFixed(1)}/${durationMetric['p(99)'].toFixed(1)} ms`,
    );
  }
  if (dropped && dropped.count > 0) {
    lines.push(`dropped iterations: ${dropped.count}`);
  }
  lines.push(`anonymous JSON: ${output}`, '');
  return `${lines.join('\n')}\n`;
}

export function handleSummary(data) {
  const report = {
    schema_version: 1,
    privacy_notice: 'Excludes target URL, hostname, username, network addresses, filesystem paths, and Git branch; includes source commit SHAs for reproducibility; review before sharing.',
    runner: {
      name: 'k6',
      version: optionalEnvironment('TREETOP_K6_VERSION'),
    },
    environment: {
      cpu_model: optionalEnvironment('TREETOP_K6_CPU_MODEL'),
      logical_cpus: optionalEnvironment('TREETOP_K6_LOGICAL_CPUS'),
      allocated_server_cpus: optionalEnvironment('TREETOP_K6_SERVER_CPUS'),
      allocated_client_cpus: optionalEnvironment('TREETOP_K6_CLIENT_CPUS'),
      os: optionalEnvironment('TREETOP_K6_OS'),
      architecture: optionalEnvironment('TREETOP_K6_ARCH'),
      kernel: optionalEnvironment('TREETOP_K6_KERNEL'),
      cpu_governor: optionalEnvironment('TREETOP_K6_CPU_GOVERNOR'),
      treetop_rest_version: optionalEnvironment('TREETOP_K6_REST_VERSION'),
      treetop_rest_sha: optionalEnvironment('TREETOP_K6_REST_SHA'),
      treetop_core_version: optionalEnvironment('TREETOP_K6_CORE_VERSION'),
      treetop_core_sha: optionalEnvironment('TREETOP_K6_CORE_SHA'),
      cedar_version: optionalEnvironment('TREETOP_K6_CEDAR_VERSION'),
    },
    configuration: {
      workload,
      mode,
      vus,
      iterations,
      duration,
      max_duration: maxDuration,
      rate,
      max_vus: maxVus,
    },
    k6_summary: data,
  };

  return {
    stdout: consoleSummary(data),
    [output]: JSON.stringify(report, null, 2),
  };
}
