#!/usr/bin/env bash
# Bash completion for bb10mt (BB10 MultiTool).
# Usage: source myapp-completion.sh
# Run ./myapp-completion.sh directly to self-check it.
# Keep _bb10mt_subcommands, _bb10mt_options and value_opts in sync with the
# command registrations in the u*.pas units.

_bb10mt_subcommands() {
  case "$1" in
    "")         echo "qnx6 unpack pack split flash info loader nuke bar raw autoloader rcfs connect batch" ;;
    qnx6)       echo "mount compact mkfs fsck script" ;;
    bar)        echo "template update ids install" ;;
    raw)        echo "dump nvram" ;;
    autoloader) echo "create extract loaders" ;;
    rcfs)       echo "modify extract vmdk" ;;
  esac
}

_bb10mt_options() {
  local common="-h --help -v --version"
  case "$1" in
    "")                   echo "$common --help-complete --completion-file --completion-file-pwsh" ;;
    "qnx6 mount")         echo "-m --mountpoint -i --image -f --foreground -d --debug $common" ;;
    "qnx6 compact")       echo "-i --image $common" ;;
    "qnx6 mkfs")          echo "-i --image -b --blocks -n --inodes -s --block-size $common" ;;
    "qnx6 fsck")          echo "-i --image -f --fix $common" ;;
    "qnx6 script")        echo "-i --image -s --script -d --debloat -b --blacklist $common" ;;
    unpack)               echo "-c --container -o --output $common" ;;
    pack)                 echo "-c --container -i --input -l --list --versions -s --sign -f --fast $common" ;;
    split)                echo "-i --input -o --output $common" ;;
    flash)                echo "-i --input -l --list --versions -r --loaders -d --delay $common" ;;
    info|loader)          echo "-d --delay $common" ;;
    nuke)                 echo "$common" ;;
    "bar template")       echo "-p --path -n --name $common" ;;
    "bar update"|"bar ids") echo "-p --path $common" ;;
    "bar install")        echo "-p --path -m --mount $common" ;;
    "raw dump")           echo "-i --input -o --output -m --mct $common" ;;
    "raw nvram")          echo "-i --input -o --output $common" ;;
    "autoloader create")  echo "-o --output -c --cap -i --input -l --list --versions $common" ;;
    "autoloader extract") echo "-i --input -c --cap $common" ;;
    "autoloader loaders") echo "-i --input -o --output $common" ;;
    "rcfs modify")        echo "-c --corrupt -s --script -i --image $common" ;;
    "rcfs extract")       echo "-i --image -o --out $common" ;;
    "rcfs vmdk")          echo "-s --script -i --image $common" ;;
    connect)              echo "-i --ip -p --password -k --sshPublicKey $common" ;;
    batch)                echo "-i --input -s --script -o --output -c --compact $common" ;;
    *)                    echo "$common" ;;
  esac
}

_bb10mt_complete() {
  local cur="${COMP_WORDS[COMP_CWORD]}" node="" w i skip=0
  # Options that consume the next word; used so an option value is not mistaken for a subcommand.
  local value_opts=" -m --mountpoint -i --image -s --script -b --blacklist --blocks --block-size -c --container -o --output --out -l --list --versions -r --loaders -d --delay -n --name --inodes -p --path --password --ip -k --sshPublicKey --corrupt --mount --mct "

  for ((i = 1; i < COMP_CWORD; i++)); do
    w=${COMP_WORDS[i]}
    if ((skip)); then skip=0; continue; fi
    case $w in
      --*=*) ;;
      -*)
        case $value_opts in *" $w "*) skip=1 ;; esac
        ;;
      *)
        case " $(_bb10mt_subcommands "$node") " in
          *" $w "*) node=${node:+$node }$w ;;
        esac
        ;;
    esac
  done

  local candidates
  if [[ $cur == -* ]]; then
    candidates=$(_bb10mt_options "$node")
  else
    candidates=$(_bb10mt_subcommands "$node")
  fi
  COMPREPLY=( $(compgen -W "$candidates" -- "$cur") )
}

complete -o default -F _bb10mt_complete bb10mt
complete -o default -F _bb10mt_complete ./bb10mt

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  _check() {
    local expected=$1; shift
    COMP_WORDS=("$@"); COMP_CWORD=$((${#COMP_WORDS[@]} - 1)); COMPREPLY=()
    _bb10mt_complete
    [[ " ${COMPREPLY[*]} " == *" $expected "* ]] || { echo "FAIL: $* -> ${COMPREPLY[*]}" >&2; exit 1; }
  }
  _check qnx6 bb10mt qnx
  _check --completion-file bb10mt --completion-
  _check template bb10mt bar ""
  _check create bb10mt autoloader ""
  _check --image bb10mt qnx6 mkfs -
  _check --image bb10mt qnx6 mkfs -i image.img -
  _check --delay bb10mt flash -
  echo "completion self-check OK"
fi
