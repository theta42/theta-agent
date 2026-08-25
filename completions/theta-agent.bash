_theta_agent_completions() {
    local cur prev cmds types services
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    cmds="register unregister list-services get-secret get-secrets verify reset-enrollment config-set reinitialize discover update install-completions install-service remove-service configure-login version help"
    types="systemd docker podman process systemd-timer cron lxc kvm libvirt"

    if [[ $COMP_CWORD -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "${cmds}" -- "${cur}") )
        return 0
    fi

    case "${COMP_WORDS[1]}" in
        register|unregister)
            if [[ $COMP_CWORD -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "${types}" -- "${cur}") )
                return 0
            fi
            if [[ $COMP_CWORD -eq 3 ]]; then
                case "${COMP_WORDS[2]}" in
                    systemd)       services=$(systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null | awk '{sub(/\.service$/,"",$1); print $1}') ;;
                    docker)        services=$(docker ps -a --format '{{.Names}}' 2>/dev/null) ;;
                    podman)        services=$(podman ps -a --format '{{.Names}}' 2>/dev/null) ;;
                    process)       services=$(ps -eo comm= 2>/dev/null | sort -u) ;;
                    systemd-timer) services=$(systemctl list-timers --no-legend --no-pager 2>/dev/null | awk '{print $NF}' | sed 's/\.timer$//') ;;
                    cron)          services=$(ls /etc/cron.d 2>/dev/null) ;;
                    lxc)           services=$(lxc-ls -1 2>/dev/null) ;;
                    kvm|libvirt)   services=$(virsh list --all --name 2>/dev/null) ;;
                esac
                COMPREPLY=( $(compgen -W "${services}" -- "${cur}") )
                return 0
            fi
            ;;
        list-services)
            return 0
            ;;
    esac
    return 0
}

complete -F _theta_agent_completions theta-agent
