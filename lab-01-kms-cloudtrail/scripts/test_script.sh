#!/usr/bin/env bash
set -euo pipefail

# -- config --


# -- helpers -- 

# -- tests --
if OUTPUT="$(aws s3 cp sample-837p-claims.csv \
  s3://hipaa-lab01-phi-landing-948285518372/incoming/ \
  --profile hipaa-labs 2>&1)"; then
  echo "Test 1 Passed: File uploaded successfully without encryption."
else
  
fi


# -- summary -- 

# cloud trail look ups 
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=Decrypt \
  --max-results 5 \
  --profile hipaa-labs \
  --no-cli-pager


  aws s3 cp \
  s3://hipaa-lab01-phi-landing-948285518372/incoming/sample-837p-claims.csv \
  ./downloaded-by-processing.csv


# test 1 - upload with no encryption
cd ~/Desktop/Projects/hipaa-aws-labs/lab-01-kms-cloudtrail/verification

aws s3 cp sample-837p-claims.csv \
  s3://hipaa-lab01-phi-landing-948285518372/incoming/ \
  --profile hipaa-labs


  # test 2 - upload with encryption
  aws s3api head-object \
  --bucket hipaa-lab01-phi-landing-948285518372 \
  --key incoming/sample-837p-claims.csv \
  --profile hipaa-labs \
  --no-cli-pager

  aws s3 cp sample-837p-claims.csv \
  s3://hipaa-lab01-phi-landing-948285518372/incoming/ \
  --sse aws:kms \
  --sse-kms-key-id alias/hipaa-lab01-phi-landing-zone \
  --profile hipaa-labs


# test 3 - download as the processing role - with both Get object and kms: decryption
aws sts assume-role \
  --role-arn arn:aws:iam::948285518372:role/hipaa-lab01-claims-processing \
  --role-session-name processing-test \
  --profile hipaa-labs \
  --no-cli-pager

aws s3 cp \
  s3://hipaa-lab01-phi-landing-948285518372/incoming/sample-837p-claims.csv \
  ./downloaded-by-processing.csv

  head -3 downloaded-by-processing.csv


# test 4 - download without correct roles 
aws sts assume-role \
  --role-arn arn:aws:iam::948285518372:role/hipaa-lab01-unauthorized-analyst \
  --role-session-name analyst-test \
  --profile hipaa-labs \
  --no-cli-pager


aws s3 cp \
  s3://hipaa-lab01-phi-landing-948285518372/incoming/sample-837p-claims.csv \
  ./downloaded-by-analyst.csv