FROM archlinux/base

# install deps
RUN pacman -Syu --noconfirm
RUN pacman --noconfirm --needed -S base-devel sudo cmake git cmocka http-parser mbedtls

# create builduser
RUN useradd builduser -m
RUN passwd -d builduser
RUN printf 'builduser ALL=(ALL) ALL\n' | tee -a /etc/sudoers

# install yay
RUN sudo -u builduser git clone https://aur.archlinux.org/yay.git /tmp/yay
RUN cd /tmp/yay && sudo -u builduser makepkg -si --noconfirm
RUN rm -rf /tmp/yay

# install AUR deps
RUN sudo -u builduser yay -S --noconfirm lcov-git
