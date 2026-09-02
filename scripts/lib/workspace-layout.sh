#!/usr/bin/env bash

midorivpn_path_is_within() {
    local path="$1"
    local root="$2"
    [[ "${path}" == "${root}" || "${path}" == "${root}/"* ]]
}

midorivpn_related_repo_has_markers() {
    local name="$1"
    local candidate="$2"
    case "${name}" in
        midori-vpn-control)
            [[ -f "${candidate}/package.json" && -f "${candidate}/.container/Containerfile" ]]
            ;;
        midori-vpn-desktop)
            [[ -f "${candidate}/package.json" && -f "${candidate}/agent/go.mod" ]]
            ;;
        midorivpn-extension)
            [[ -f "${candidate}/package.json" && -f "${candidate}/manifest/main.json" ]]
            ;;
        *)
            return 1
            ;;
    esac
}

midorivpn_resolve_related_repo() {
    local core_dir="$1"
    local name="$2"
    local candidate
    for candidate in "${core_dir}/${name}" "$(dirname "${core_dir}")/${name}"; do
        if [[ -d "${candidate}" ]] && midorivpn_related_repo_has_markers "${name}" "${candidate}"; then
            (cd "${candidate}" && pwd -P)
            return
        fi
    done
    return 1
}

midorivpn_container_repo_root() {
    local core_dir="$1"
    local host_dir="$2"
    local name="$3"
    local relative
    if midorivpn_path_is_within "${host_dir}" "${core_dir}"; then
        relative="${host_dir#${core_dir}}"
        relative="${relative#/}"
        if [[ -z "${relative}" ]]; then
            echo "/workspace"
        else
            echo "/workspace/${relative}"
        fi
    else
        echo "/external/${name}"
    fi
}
