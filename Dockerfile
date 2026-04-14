# syntax=docker/dockerfile:1
FROM python:3.12-slim

LABEL org.opencontainers.image.title="skillscan-fuzzer" \
      org.opencontainers.image.description="LLM-powered adversarial skill file fuzzer for skillscan-security" \
      org.opencontainers.image.url="https://skillscan.sh" \
      org.opencontainers.image.source="https://github.com/kurtpayne/skillscan-fuzzer" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN pip install --no-cache-dir skillscan-fuzzer

WORKDIR /scan

ENTRYPOINT ["skillscan-fuzzer"]
CMD ["--help"]
