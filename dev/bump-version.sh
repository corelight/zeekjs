#!/bin/bash
#
# Create a commit that just bumps the VERSION file and also creates a tag,
# then outputs the push command.
set -eu

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <version>" >&2
  exit 1
fi

if [[ ! $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "error: bad version $1" >&2
    exit 1
fi

new_version=$1
tag="v${1}"

current_branch="$(git rev-parse --abbrev-ref HEAD)"

if [ "${current_branch}" != "main" ]; then
  echo "error: not on main branch: $current_branch" >&2
  exit 1
fi

if git cat-file -t "$tag" >/dev/null 2>&1; then
  echo "error: tag $tag exists" >&2
  exit 1
fi

echo "$new_version" > VERSION
git add VERSION

git commit -m "version: ${new_version}"
git tag "v${new_version}"

echo "git push origin main v${new_version}"
