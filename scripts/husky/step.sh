#!/usr/bin/env bash

COLOR_GREEN='\033[0;32m'
COLOR_RED='\033[0;31m'
COLOR_RESET='\033[0m'

# Executes a shell command with a loading indicator and formatted output.
#
# It captures the standard output (stdout) and standard error (stderr) of the
# command. Before printing the final result, it looks for an optional user-defined
# `handle_output` function, allowing you to intercept and modify the output
# or the success message based on the command's exit code.
#
# Arguments:
#   $1 - PROGRESS_MSG : The message to display while the command is running.
#   $2 - SUCCESS_MSG  : The default message to display if the command succeeds.
#   $@ - COMMAND      : The actual shell command and its arguments to execute.
#
# Optional Hook:
#   If a function named `handle_output` is declared in the calling script,
#   `run_step` will automatically invoke it before finishing.
#
#   Arguments passed to `handle_output`:
#     $1 - EXIT_CODE : The exit code of the executed command (0 for success).
#
#   Global variables available inside `handle_output` (can be modified):
#     RESULT         : The captured stdout and stderr of the command.
#     SUCCESS_MSG : The success message (can be overwritten based on RESULT).
#     ERROR_MSG   : The error message (defaults to "$PROGRESS_MSG failed").
#
# Example usage:
# ```bash
# source utils.sh
#
# # 1. Define the optional hook (if you need custom logic)
# handle_output() {
#   local EXIT_CODE=$1
#
#   if [ $EXIT_CODE -eq 0 ]; then
#     if [[ "$RESULT" == *"OK"* ]]; then
#       SUCCESS_MSG="Overridden success message"
#     fi
#   else
#     if [[ "$RESULT" == *"ERROR"* ]]; then
#       ERROR_MSG="Overridden success message"
#     fi
#   fi
# }
#
# # 2. Run the commands
# run_step "Verifying lockfile" "Lockfile verified" yarn install --immutable
# run_step "Linting files" "Linting passed" yarn eslint
# ```
run_step() {
  PROGRESS_MSG="$1"
  SUCCESS_MSG="$2"
  ERROR_MSG="$PROGRESS_MSG failed"
  shift 2

  printf "⏳ %-45s" "$PROGRESS_MSG..."

  RESULT=$("$@" 2>&1)
  EXIT_CODE=$?

  if declare -f handle_output > /dev/null; then
    handle_output $EXIT_CODE
  fi

  if [ $EXIT_CODE -eq 0 ]; then
    printf "\r${COLOR_GREEN}✨ %-45s${COLOR_RESET}\n" "$SUCCESS_MSG"
  else
    printf "\r${COLOR_RED}❌ %-45s${COLOR_RESET}\n" "$ERROR_MSG"
    echo ""
    echo "$RESULT"
    exit 1
  fi
}
