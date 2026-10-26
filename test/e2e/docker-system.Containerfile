ARG DAKOTA_BASE
FROM ${DAKOTA_BASE}
# Dakota has no distro package manager. Install real upstream packages only in
# this disposable test image, through Docker's signed Debian repository chain.
# No maintainer scripts, ChairLift installers, or host package changes run.
COPY docker_image_packages.py /tmp/chairlift-docker-image-packages.py
RUN python3 /tmp/chairlift-docker-image-packages.py && rm /tmp/chairlift-docker-image-packages.py
