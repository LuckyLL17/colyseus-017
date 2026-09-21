#!/bin/bash

# Script to sync fork with upstream repository
# Upstream: https://github.com/better-auth/better-call.git
# Origin: git@github.com:colyseus/better-call.git

set -e

UPSTREAM_URL="git@github.com:better-auth/better-call.git"
UPSTREAM_BRANCH="main"

# Check if upstream remote exists, add if not
if ! git remote | grep -q "^upstream$"; then
    echo "Adding upstream remote..."
    git remote add upstream "$UPSTREAM_URL"
else
    # Ensure upstream remote has correct URL and fetch refspec
    git remote set-url upstream "$UPSTREAM_URL"
    git config remote.upstream.fetch "+refs/heads/*:refs/remotes/upstream/*"
fi

echo "Fetching upstream..."
if ! git fetch upstream; then
    echo "Error: Failed to fetch upstream. Check your network connection."
    exit 1
fi

# Verify upstream/main exists
if ! git rev-parse --verify upstream/$UPSTREAM_BRANCH >/dev/null 2>&1; then
    echo "Error: upstream/$UPSTREAM_BRANCH not found after fetch."
    exit 1
fi

echo "Checking out main branch..."
git checkout main

echo "Merging upstream/main into main..."
git merge upstream/$UPSTREAM_BRANCH

echo "✓ Successfully synced with upstream!"
