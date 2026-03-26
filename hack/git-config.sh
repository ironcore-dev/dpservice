#!/bin/bash

git config --global url."https://gitlab-ci-token:${CI_JOB_TOKEN}@gitlab.devops.telekom.de/".insteadOf "https://gitlab.devops.telekom.de/"
echo machine gitlab.devops.telekom.de login gitlab-ci-token password ${CI_JOB_TOKEN} > $HOME/.netrc
