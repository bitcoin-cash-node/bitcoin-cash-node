#!/usr/bin/env python3

import argparse
import inspect
import multiprocessing
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

# Codes for bold red warning formatting are no-ops unless on POSIX
BOLD, RED = ('', ''), ('', ''),
if os.name == 'posix':
    # primitive formatting on supported
    # terminal via ANSI escape sequences:
    BOLD = ('\033[0m', '\033[1m')
    RED = ('\033[0m', '\033[0;31m')

is_mac = sys.platform == 'darwin'


def setup():
    global args, builder_dir, workdir
    if not is_mac:
        programs = ['ruby', 'git', 'apt-cacher-ng', 'make', 'wget']
        if args.kvm:
            programs += ['python-vm-builder', 'qemu-kvm', 'qemu-utils']
        elif args.docker:
            dockers = ['docker.io', 'docker-ce']
            for i in dockers:
                return_code = subprocess.call(
                    ['sudo', 'apt-get', 'install', '-qq', i])
                if return_code == 0:
                    break
            if return_code != 0:
                print('Cannot find any way to install docker', file=sys.stderr)
                exit(1)
        else:
            programs += ['lxc', 'debootstrap']
        subprocess.check_call(['sudo', 'apt-get', 'install', '-qq'] + programs)
    else:
        if args.docker:
            print("Warning: macOS support is experimental and requires docker be already installed", file=sys.stderr)
        else:
            sys.exit("macOS support only works in --docker mode")

    if not Path('gitian-build.py').is_file():
        # Copy the currently running gitian-build.py script into the current dir for convenience
        print("Copying {} -> {}".format(Path(__file__).relative_to(workdir, walk_up=True), 'gitian-build.py'))
        shutil.copy(__file__, 'gitian-build.py')

    # Fetch gitian-builder directory
    if not builder_dir.is_dir():
        if builder_dir.exists():
            builder_dir.unlink()
        # If we are next to bitcoin-cash-node, just copy from there. Otherwise get latest from master
        if os.path.isdir('bitcoin-cash-node'):
            src = Path('bitcoin-cash-node/contrib/gitian-builder')
            print("Copying {} -> {}".format(src, builder_dir))
            shutil.copytree(src, builder_dir)
        else:
            with tempfile.TemporaryDirectory() as tmpdir:
                os.chdir(tmpdir)
                gitlab_repo = 'https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node.git'
                subprocess.check_call(['git', 'clone', '--no-checkout', '--depth=1', '--no-tags', gitlab_repo])
                os.chdir('bitcoin-cash-node')
                subprocess.check_call(['git', 'restore', '--staged', 'contrib/gitian-builder'])
                subprocess.check_call(['git', 'checkout', 'contrib/gitian-builder'])
                src = 'contrib/gitian-builder'
                print("Copying {}:{} -> {}".format(gitlab_repo, src, builder_dir))
                shutil.copytree(src, builder_dir)

    os.chdir(builder_dir)
    make_image_prog = ['bin/make-base-vm',
                       '--distro', 'ubuntu', '--suite', 'jammy', '--arch', 'amd64']
    if args.docker:
        make_image_prog += ['--docker']
    elif not args.kvm:
        make_image_prog += ['--lxc']
    subprocess.check_call(make_image_prog)
    os.chdir(workdir)
    if args.is_bionic and not args.kvm and not args.docker:
        subprocess.check_call(
            ['sudo', 'sed', '-i', 's/lxcbr0/br0/', '/etc/default/lxc-net'])
        print('Reboot is required')
        exit(0)


DESCRIPTORS_DIR = 'inputs/bitcoin/contrib/gitian-descriptors/'


def build():
    global args, builder_dir, workdir

    base_output_dir = 'bitcoin-binaries/' + args.version
    os.makedirs(base_output_dir + '/src', exist_ok=True)
    print('\nBuilding Dependencies\n')
    os.chdir(builder_dir)
    os.makedirs('inputs', exist_ok=True)

    subprocess.check_call(['make', '-C', 'inputs/bitcoin/depends',
                           'download', 'SOURCES_PATH=' + os.getcwd() + '/cache/common'])

    output_dir_src = '../' + base_output_dir + '/src'
    if args.linux:
        print('\nCompiling ' + args.version + ' Linux')
        subprocess.check_call(['bin/gbuild', '-j', args.jobs, '-m', args.memory, '--commit', 'bitcoin=' + args.commit,
                               '--url', 'bitcoin=' + args.url, DESCRIPTORS_DIR + 'gitian-linux.yml'])
        subprocess.check_call(['bin/gsign', '-p', args.sign_prog, '--signer', args.signer, '--release', args.version +
                               '-linux', '--destination', '../gitian.sigs/', DESCRIPTORS_DIR + 'gitian-linux.yml'])
        output_dir_linux = '../' + base_output_dir + '/linux'
        os.makedirs(output_dir_linux, exist_ok=True)
        subprocess.check_call(
            'mv build/out/bitcoin-*.tar.gz ' + output_dir_linux, shell=True)
        subprocess.check_call(
            'mv build/out/src/bitcoin-*.tar.gz ' + output_dir_src, shell=True)
        subprocess.check_call(
            'mv result/bitcoin-*-linux-res.yml ' + output_dir_linux, shell=True)

    if args.windows:
        print('\nCompiling ' + args.version + ' Windows')
        subprocess.check_call(['bin/gbuild', '-j', args.jobs, '-m', args.memory, '--commit', 'bitcoin=' + args.commit,
                               '--url', 'bitcoin=' + args.url, DESCRIPTORS_DIR + 'gitian-win.yml'])
        subprocess.check_call(['bin/gsign', '-p', args.sign_prog, '--signer', args.signer, '--release', args.version +
                               '-win-unsigned', '--destination', '../gitian.sigs/', DESCRIPTORS_DIR + 'gitian-win.yml'])
        output_dir_win = '../' + base_output_dir + '/win'
        os.makedirs(output_dir_win, exist_ok=True)
        subprocess.check_call(
            'mv build/out/bitcoin-*-win-unsigned.tar.gz inputs/', shell=True)
        subprocess.check_call(
            'mv build/out/bitcoin-*.zip build/out/bitcoin-*.exe ' + output_dir_win, shell=True)
        subprocess.check_call(
            'mv build/out/src/bitcoin-*.tar.gz ' + output_dir_src, shell=True)
        subprocess.check_call(
            'mv result/bitcoin-*-win-res.yml ' + output_dir_win, shell=True)

    if args.macos:
        print('\nCompiling ' + args.version + ' MacOS')
        subprocess.check_call(['bin/gbuild', '-j', args.jobs, '-m', args.memory, '--commit', 'bitcoin=' + args.commit,
                               '--url', 'bitcoin=' + args.url, DESCRIPTORS_DIR + 'gitian-osx.yml'])
        subprocess.check_call(['bin/gsign', '-p', args.sign_prog, '--signer', args.signer, '--release', args.version +
                               '-osx-unsigned', '--destination', '../gitian.sigs/', DESCRIPTORS_DIR + 'gitian-osx.yml'])
        output_dir_osx = '../' + base_output_dir + '/osx'
        os.makedirs(output_dir_osx, exist_ok=True)
        subprocess.check_call(
            'mv build/out/bitcoin-*.tar.gz build/out/bitcoin-*.dmg ' + output_dir_osx, shell=True)
        subprocess.check_call(
            'mv build/out/src/bitcoin-*.tar.gz ' + output_dir_src, shell=True)
        subprocess.check_call(
            'mv result/bitcoin-*-osx-res.yml ' + output_dir_osx, shell=True)

    os.chdir(workdir)

    if args.commit_files:
        print('\nCommitting ' + args.version + ' Unsigned Sigs\n')
        os.chdir('gitian.sigs')
        subprocess.check_call(
            ['git', 'add', args.version + '-linux/' + args.signer])
        subprocess.check_call(
            ['git', 'add', args.version + '-win-unsigned/' + args.signer])
        subprocess.check_call(
            ['git', 'add', args.version + '-osx-unsigned/' + args.signer])
        subprocess.check_call(
            ['git', 'commit', '-m', 'Add ' + args.version + ' unsigned sigs for ' + args.signer])
        os.chdir(workdir)


def sign():
    global args, builder_dir, workdir
    os.chdir(builder_dir)

    if args.windows:
        print('\nSigning ' + args.version + ' Windows')
        subprocess.check_call('cp inputs/bitcoin-' + args.version +
                              '-win-unsigned.tar.gz inputs/bitcoin-win-unsigned.tar.gz', shell=True)
        subprocess.check_call(['bin/gbuild', '-i', '--commit', 'signature=' + args.commit,
                               DESCRIPTORS_DIR + 'gitian-win-signer.yml'])
        subprocess.check_call(['bin/gsign', '-p', args.sign_prog, '--signer', args.signer, '--release', args.version + '-win-signed',
                               '--destination', '../gitian.sigs/', DESCRIPTORS_DIR + 'gitian-win-signer.yml'])
        subprocess.check_call(
            'mv build/out/bitcoin-*win64-setup.exe ../bitcoin-binaries/' + args.version, shell=True)

    if args.macos:
        print('\nSigning ' + args.version + ' MacOS')
        subprocess.check_call('cp inputs/bitcoin-' + args.version +
                              '-aarch64-apple-darwin-unsigned.tar.gz inputs/bitcoin-osx-unsigned.tar.gz', shell=True)
        subprocess.check_call(['bin/gbuild', '-i', '--commit', 'signature=' + args.commit,
                               DESCRIPTORS_DIR + 'gitian-osx-signer.yml'])
        subprocess.check_call(['bin/gsign', '-p', args.sign_prog, '--signer', args.signer, '--release', args.version + '-osx-signed',
                               '--destination', '../gitian.sigs/', DESCRIPTORS_DIR + 'gitian-osx-signer.yml'])
        subprocess.check_call('mv build/out/bitcoin-osx-signed.dmg ../bitcoin-binaries/' +
                              args.version + '/bitcoin-' + args.version + '-osx.dmg', shell=True)

    os.chdir(workdir)

    if args.commit_files:
        print('\nCommitting ' + args.version + ' Signed Sigs\n')
        os.chdir('gitian.sigs')
        subprocess.check_call(
            ['git', 'add', args.version + '-win-signed/' + args.signer])
        subprocess.check_call(
            ['git', 'add', args.version + '-osx-signed/' + args.signer])
        subprocess.check_call(['git', 'commit', '-a', '-m', 'Add ' +
                               args.version + ' signed binary sigs for ' + args.signer])
        os.chdir(workdir)


def verify():
    global args, builder_dir, workdir
    os.chdir(builder_dir)

    print('\nVerifying v' + args.version + ' Linux\n')
    subprocess.check_call(['bin/gverify', '-v', '-d', '../gitian.sigs/', '-r', args.version +
                           '-linux', DESCRIPTORS_DIR + 'gitian-linux.yml'])
    print('\nVerifying v' + args.version + ' Windows\n')
    subprocess.check_call(['bin/gverify', '-v', '-d', '../gitian.sigs/', '-r', args.version +
                           '-win-unsigned', DESCRIPTORS_DIR + 'gitian-win.yml'])
    print('\nVerifying v' + args.version + ' MacOS\n')
    subprocess.check_call(['bin/gverify', '-v', '-d', '../gitian.sigs/', '-r', args.version +
                           '-osx-unsigned', DESCRIPTORS_DIR + 'gitian-osx.yml'])
    print('\nVerifying v' + args.version + ' Signed Windows\n')
    subprocess.check_call(['bin/gverify', '-v', '-d', '../gitian.sigs/', '-r', args.version +
                           '-win-signed', DESCRIPTORS_DIR + 'gitian-win-signer.yml'])
    print('\nVerifying v' + args.version + ' Signed MacOS\n')
    subprocess.check_call(['bin/gverify', '-v', '-d', '../gitian.sigs/', '-r', args.version +
                           '-osx-signed', DESCRIPTORS_DIR + 'gitian-osx-signer.yml'])

    os.chdir(workdir)


def main():
    global args, builder_dir, workdir
    num_cpus = multiprocessing.cpu_count()

    parser = argparse.ArgumentParser(description='Script for running full Gitian builds.')
    parser.add_argument('-c', '--commit', action='store_true', dest='commit',
                        help='Indicate that the version argument is for a commit or branch')
    parser.add_argument('-R', '--merge-request', action='store_true', dest='merge_request',
                        help='Indicate that the version argument is the number of a GitLab merge request')
    parser.add_argument('-u', '--url', dest='url', default='https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node.git',
                        help='Specify the URL of the repository. Default is %(default)s')
    parser.add_argument('-v', '--verify', action='store_true',
                        dest='verify', help='Verify the Gitian build')
    parser.add_argument('-b', '--build', action='store_true',
                        dest='build', help='Do a Gitian build')
    parser.add_argument('-s', '--sign', action='store_true', dest='sign',
                        help='Make signed binaries for Windows and MacOS')
    parser.add_argument('-B', '--buildsign', action='store_true',
                        dest='buildsign', help='Build both signed and unsigned binaries')
    parser.add_argument('-o', '--os', dest='os', default='lwm',
                        help='Specify which Operating Systems the build is for. Default is %(default)s. l for Linux, w for Windows, m for MacOS')
    parser.add_argument('-j', '--jobs', dest='jobs', default=str(num_cpus),
                        help='Number of processes to use. Default %(default)s')
    parser.add_argument('-m', '--memory', dest='memory', default='3500',
                        help='Memory to allocate in MiB. Default %(default)s')
    parser.add_argument('-k', '--kvm', action='store_true',
                        dest='kvm', help='Use KVM instead of LXC')
    parser.add_argument('-d', '--docker', action='store_true',
                        dest='docker', help='Use Docker instead of LXC')
    parser.add_argument('-S', '--setup', action='store_true', dest='setup',
                        help='Set up the Gitian building environment. Uses LXC. If you want to use KVM, use the --kvm option. Only works on Debian-based systems (Ubuntu, Debian)')
    parser.add_argument('-D', '--detach-sign', action='store_true', dest='detach_sign',
                        help='Create the assert file for detached signing. Will not commit anything.')
    parser.add_argument('-n', '--no-commit', action='store_false',
                        dest='commit_files', help='Do not commit anything to git')
    parser.add_argument(
        'signer', nargs='?', help='GPG signer to sign each build assert file')
    parser.add_argument(
        'version', nargs='?', help='Version number, commit, or branch to build. If building a commit or branch, the -c option must be specified')

    args = parser.parse_args()
    workdir = Path.cwd()
    builder_dir = workdir / 'gitian-builder'

    args.is_bionic = not is_mac and b'bionic' in subprocess.check_output(
        ['lsb_release', '-cs'])

    if args.kvm and args.docker:
        raise Exception('Error: cannot have both kvm and docker')

    # Set environment variable USE_LXC or USE_DOCKER, let gitian-builder know
    # that we use lxc or docker
    if args.docker:
        os.environ.pop('USE_LXC', None)
        os.environ['USE_DOCKER'] = '1'
    elif args.kvm:
        os.environ.pop('USE_LXC', None)
        os.environ.pop('USE_DOCKER', None)
    else:
        os.environ['USE_LXC'] = '1'
        os.environ.pop('USE_DOCKER', None)
        if 'GITIAN_HOST_IP' not in os.environ.keys():
            os.environ['GITIAN_HOST_IP'] = '10.0.3.1'
        if 'LXC_GUEST_IP' not in os.environ.keys():
            os.environ['LXC_GUEST_IP'] = '10.0.3.5'

    if args.setup:
        setup()

    if args.buildsign:
        args.build = True
        args.sign = True

    if not args.build and not args.sign and not args.verify:
        sys.exit(0)

    args.linux = 'l' in args.os
    args.windows = 'w' in args.os
    args.macos = 'm' in args.os

    # Disable for MacOS if no SDK found
    if args.macos and not Path('gitian-builder/inputs/MacOSX14.5.sdk.tar.xz').is_file():
        print('Cannot build for MacOS, SDK does not exist. Will build for other OSes')
        args.macos = False

    args.sign_prog = 'true' if args.detach_sign else 'gpg --detach-sign'

    script_name = Path(sys.argv[0]).name
    # Signer and version shouldn't be empty
    if not args.signer:
        print(script_name + ': Missing signer.')
        print('Try ' + script_name + ' --help for more information')
        exit(1)
    if not args.version:
        print(script_name + ': Missing version.')
        print('Try ' + script_name + ' --help for more information')
        exit(1)

    # Add leading 'v' for tags
    if args.commit and args.merge_request:
        raise Exception('Cannot have both commit and merge request')
    args.commit = ('' if args.commit else 'v') + args.version

    # If this is the first time you run gitian_build you never had a chance of initialize
    # the project repo inside gitian-builder directory, in fact this is usually done by
    # gitian-builder/bin/gbuild ruby script.
    if not Path('gitian-builder/inputs/bitcoin').is_dir():
        subprocess.check_call(['mkdir', '-p', 'gitian-builder/inputs'])
        os.chdir('gitian-builder/inputs')
        subprocess.check_call(['git', 'clone', args.url, 'bitcoin'])

    # Update inputs/bitcoin/ to the commit to build
    os.chdir(workdir / 'gitian-builder/inputs/bitcoin')

    subprocess.check_call(['git', 'fetch'])
    if args.merge_request:
        subprocess.check_call(
            ['git', 'fetch', args.url, 'merge-requests/' + args.version + '/head:mr-' + args.version])
        args.version = 'mr-' + args.version
        args.commit = subprocess.check_output(['git', 'show', '-s', '--format=%H', 'FETCH_HEAD'],
                                              universal_newlines=True, encoding='utf8').strip()
    subprocess.check_call(['git', 'checkout', args.commit])

    # Compare our own source code to bitcoin-cash-node version of gitian-build.py
    # and raise a warning if it differs.
    # Need to add newlines back in order to diff against file.
    our_source = [line + '\n' for line in
                  inspect.getsource(inspect.getmodule(inspect.currentframe())).splitlines()]
    with open('contrib/gitian-build.py', 'r', encoding='utf-8') as script_file:
        script_source = script_file.readlines()
        if our_source != script_source:
            print(BOLD[1] + RED[1] + '*' * 70)
            print("WARNING: gitian-build.py you are running differs from the one in\n"
                  "         the source you are building!\n"
                  "         If this is unexpected, please check whether you need to\n"
                  "         copy the source tree's version to your top level build\n"
                  "         directory.")
            print('*' * 70 + RED[0] + BOLD[0])

    # Head back to work dir, show some diagnostics before kicking off the build.
    os.chdir(workdir)
    print("cwd:", Path.cwd())
    print("commit:", args.commit)

    if args.build:
        build()

    if args.sign:
        sign()

    if args.verify:
        verify()

    os.chdir(workdir)


if __name__ == '__main__':
    main()
