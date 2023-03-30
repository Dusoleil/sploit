FROM archlinux

RUN pacman-key --init \
 && pacman -Syyu --needed --noconfirm git netcat python python-pip radare2 \
 && pacman -Scc --noconfirm

COPY . /sploit
RUN pip install /sploit

WORKDIR /home
ENTRYPOINT ["/sploit/docker-entry.sh"]
CMD ["--help"]
