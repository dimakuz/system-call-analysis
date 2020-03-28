# system-call-analysis

Scripts and utilities to trace system calls of workloads, utilizing bpftrace, podman and pandas

To set up the python env: `pipenv install`

To describe a new workload, refer to `postgres.yaml`

```yaml
container:
  image: postgres
  env:
    POSTGRES_PASSWORD: somepassword
  setup_commands:
    - pgbench -U postgres -s 100 -i
  test_commands:
    - pgbench -U postgres -j 50 -T 5
bpftrace_script: 'bpftrace/syscall-intervals-3.bt'
```

To run the environment: `pipenv run harness path/to/file.yaml`
Upon completion, a graph will pop open in the systemd-defined browser.
