#!/bin/bash

cosign-main(){
  img_mtr_path=$1
  commit=$2

  echo "[INFO] Cosign login to MTR ..."
  cosign login "${OSC_HOST}" -u "${MTR_GITLAB_LOGIN}" -p "${MTR_GITLAB_PASSWORD}"

  echo "[INFO] Checking image digest from MTR ..."
  image_digest=$(curl -sS -X GET \
    -H "Authorization: Bearer $MTR_GITLAB_TOKEN" \
    "https://${OSC_HOST}/api/v1/repository/${img_mtr_path}" | \
    jq -er --arg tag "$commit" '.tags[$tag].manifest_digest')

  echo "Image digest: $image_digest"

  if [[ -z $image_digest ]] || [[ $image_digest == "null" ]]; then
    echo "[WARNING] Unable to check image digest from MTR"
  else
    echo "[INFO] Signing image in MTR via cosign ..."
    yes y | cosign sign "${MTR_GITLAB_HOST}/${img_mtr_path}@${image_digest}" --key "${OSC_COSIGN_KEY}"

    echo "[INFO] Verifying signature for image in MTR ..."
    cosign verify "${MTR_GITLAB_HOST}/${img_mtr_path}@${image_digest}" --key "${OSC_COSIGN_KEY_PUB}" | jq -er .
  fi
}