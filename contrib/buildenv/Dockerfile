ARG BASE=debian:bookworm-slim
FROM $BASE

ENV DEBIAN_FRONTEND=noninteractive \
  APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=true \
  LANG=en_US.UTF-8 \
  LANGUAGE=en_US:en \
  LC_ALL=en_US.UTF-8 \
  PATH="/usr/share/arcanist/bin:${PATH}"


# Disable installation of suggested and recommended packages
RUN echo 'APT::Install-Suggests "false";' >> /etc/apt/apt.conf && \
  echo 'APT::Install-Recommends "false";' >> /etc/apt/apt.conf && \
echo && \
echo initial package manager config and requirements, silence apt interactive warnings && \
echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections && \
  apt-get -y update && \
  apt-get -y install \
    apt-utils \
    && \
  apt-get upgrade -y && \
  echo minimal components to allow us to add repos and keys && \
  apt-get -y install \
    ca-certificates \
    gnupg \
    wget && \
echo && \
echo Add LLVM repos and key for clang-18 && \
echo "deb http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-18 main" >> /etc/apt/sources.list && \
echo "deb-src http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-18 main" >> /etc/apt/sources.list && \
wget -O /etc/llvm-snapshot.gpg.key https://apt.llvm.org/llvm-snapshot.gpg.key 2>&1 && \
apt-key add /etc/llvm-snapshot.gpg.key && \
echo && \
echo install required packages && \
apt-get -y update && \
  apt-get upgrade -y && \
echo && \
echo system and build tools && \
apt-get -y install \
    apt-utils \
    autoconf \
    automake \
    bash \
    curl \
    gperf \
    libtool \
    locales \
    pkg-config \
    unzip \
    wget && \
echo && \
echo Make sure UTF-8 isnt borked && \
echo "en_US UTF-8" > /etc/locale.gen && \
  echo Add de_DE.UTF-8 for specific JSON number formatting unit tests && \
  echo "de_DE.UTF-8 UTF-8" >> /etc/locale.gen && \
  echo Generate all locales && \
  locale-gen && \
echo && \
echo BCHN build requirements && \
apt-get -y install bison \
    bsdmainutils \
    build-essential \
    ccache \
    cmake \
    libboost-chrono-dev \
    libboost-filesystem-dev \
    libboost-system-dev \
    libboost-test-dev \
    libboost-thread-dev \
    libdb++-dev \
    libdb-dev \
    libevent-dev \
    libgmp-dev \
    libminiupnpc-dev \
    libnatpmp-dev \
    libprotobuf-dev \
    libqrencode-dev \
    libqt5core5a \
    libqt5dbus5 \
    libqt5gui5 \
    libssl-dev \
    libzmq3-dev \
    protobuf-compiler \
    python3 \
    python3-zmq \
    qttools5-dev \
    qttools5-dev-tools \
    ninja-build && \
echo && \
echo Support windows build && \
apt-get -y install g++-mingw-w64-x86-64 && \
echo && \
echo Support ARM build && \
apt-get -y install g++-arm-linux-gnueabihf gcc-arm-linux-gnueabihf && \
echo && \
echo Support AArch64 build && \
apt-get -y install gcc-aarch64-linux-gnu \
    g++-aarch64-linux-gnu \
    qemu-user-static && \
echo && \
echo Support OSX build && \
apt-get -y install python3-setuptools && \
echo && \
echo Support clang build && \
apt-get -y install clang-18 && \
echo Add clang sanitizers && \
apt-get -y install libclang-rt-18-dev && \
echo && \
echo Add tools for static checking and Gitlab CI processing of results && \
apt-get -y install \
    clang-format-18 \
    eatmydata \
    git \
    nodejs \
    npm \
    python3-dev \
    python3-pip \
    python3-venv \
    php-codesniffer \
    php-curl \
    shellcheck \
    xmlstarlet \
    && \
git clone https://github.com/phorgeit/arcanist.git /usr/share/arcanist && \
python3 -m venv /opt/venv && \
. /opt/venv/bin/activate && \
python3 -m pip install \
    autopep8 \
    flake8 \
    jinja2 \
    mkdocs \
    mkdocs-material \
    packaging \
    pymdown-extensions \
    scipy \
    && \
echo && \
echo && \
echo Support windows build && \
update-alternatives --set x86_64-w64-mingw32-g++ /usr/bin/x86_64-w64-mingw32-g++-posix && \
update-alternatives --set x86_64-w64-mingw32-gcc /usr/bin/x86_64-w64-mingw32-gcc-posix && \
echo && \
echo Linters for documentation && \
npm install -g node@latest && \
npm install -g npm@latest && \
npm install -g markdownlint-cli && \
echo && \
echo Linter dependencies && \
apt-get install -y flake8 mypy yamllint && \
echo && \
echo Cleanup && \
apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /usr/share/doc/* /var/cache/* /var/log/* /usr/share/arcanist/.git

