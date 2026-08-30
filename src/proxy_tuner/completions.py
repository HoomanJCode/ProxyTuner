"""Shell completion generation for bash, zsh, and fish.

Provides click-based completion scripts that can be sourced
in shell profiles.
"""

from __future__ import annotations

import click

BASH_COMPLETE = '''\
_proxy-tuner_completions() {{
    local IFS=$'\\n'
    local reply

    COMPREPLY=()
    compgen -W "$({complete_command})" -- "$COMP_WORD" | while read -r line; do
        COMPREPLY+=("$line")
    done
}}

complete -F _proxy-tuner_completions proxy-tuner
'''

ZSH_COMPLETE = '''\
#compdef proxy-tuner

_proxy-tuner() {{
    eval "$(env COMMANDLINE="${words[1,$CURRENT]}" proxy-tuner -- completions zsh)"
}}

if [[ "$(basename -- {{(%):-%x}})" != "_proxy-tuner" ]]; then
    compdef _proxy-tuner proxy-tuner
fi
'''

FISH_COMPLETE = '''\
function __proxy_tuner_completions
    set -l cmd (commandline -opc)
    set -l completions (env COMMANDLINE="$cmd" proxy-tuner -- completions fish)
    for completion in $completions
        echo $completion
    end
end

complete -c proxy-tuner -f -a '(__proxy_tuner_completions)'
'''


def get_bash_completion() -> str:
    """Return bash completion script."""
    return BASH_COMPLETE


def get_zsh_completion() -> str:
    """Return zsh completion script."""
    return ZSH_COMPLETE


def get_fish_completion() -> str:
    """Return fish completion script."""
    return FISH_COMPLETE


@click.group("completions")
def completions_group() -> None:
    """Shell completion scripts."""


@completions_group.command("bash")
def bash_completion() -> None:
    """Print bash completion script."""
    click.echo(get_bash_completion())


@completions_group.command("zsh")
def zsh_completion() -> None:
    """Print zsh completion script."""
    click.echo(get_zsh_completion())


@completions_group.command("fish")
def fish_completion() -> None:
    """Print fish completion script."""
    click.echo(get_fish_completion())
