# TEST LAB ONLY — a deliberately compromised target used to verify the assessment engine.
# It contains a fake webshell, an exposed .env, SEO-cloaking spam and a fake "miner" process.
# Never deploy this image anywhere real.
FROM debian:bookworm-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       openssh-server clamav yara python3 procps iproute2 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Login user for the assessment (password auth; lab only).
RUN useradd -m -s /bin/bash ops && echo 'ops:LabOnly-Passw0rd!' | chpasswd \
    && printf 'PermitRootLogin yes\nPasswordAuthentication yes\n' > /etc/ssh/sshd_config.d/lab.conf

COPY site/ /var/www/site/
COPY server.py /opt/lab/server.py
COPY start.sh /opt/lab/start.sh
RUN chmod +x /opt/lab/start.sh && chown -R ops:ops /var/www/site

EXPOSE 22 8080
CMD ["/opt/lab/start.sh"]
