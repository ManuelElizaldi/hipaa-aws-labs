#!/usr/bin/env bash
set -euo pipefail

# -- helpers -- 
# Date for logging
DAY=$(date +%F)
FAILURES=()

# Profile
PROFILE="hipaa-labs"
# Account ID
ACCOUNT_ID=$(aws sts get-caller-identity --profile "$PROFILE" --no-cli-pager --output text --query Account)         
# Bucket 
BUCKET_NAME="hipaa-lab01-phi-landing-${ACCOUNT_ID}"
#KMS Alias S3
S3_KMS_KEY_ALIAS="alias/hipaa-lab01-phi-landing-zone"
# Processing Role
PROCESSING_ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/hipaa-lab01-claims-processing"
# KMS key for s3
S3_KMS_KEY_ARN=$(aws kms describe-key   --key-id "$S3_KMS_KEY_ALIAS"  --profile "$PROFILE"   --no-cli-pager --output text --query KeyMetadata.Arn)

# Test 1 - upload without encryption - should fail due to bucket policy
OUTPUT="$(aws s3 cp sample-837p-claims.csv \
  s3://"${BUCKET_NAME}"/incoming/ \
  --profile "$PROFILE" 2>&1)" || true 

if [[ "$OUTPUT" == *"with an explicit deny in a resource-based policy"* ]]; then
    echo "Test 1 PASS: unencrypted upload denied by bucket policy"
else
    echo "$OUTPUT"
    echo "Test 1 FAILED - unencrypted upload"
  FAILURES+=("Test 1 FAILED - unencrypted upload")
fi


# test 2 - upload with encryption upload: ./sample-837p-claims.csv to s3://hipaa-lab01-phi-landing-948285518372/incoming/sample-837p-claims.csv
OUTPUT="$(aws s3 cp sample-837p-claims.csv \
s3://"${BUCKET_NAME}"/incoming/ \
--sse aws:kms \
--sse-kms-key-id "${S3_KMS_KEY_ALIAS}" \
--profile "$PROFILE" 2>&1)" || true

if [[ "$OUTPUT" == *"upload: ./sample-837p-claims.csv to s3://${BUCKET_NAME}/incoming/sample-837p-claims.csv"* ]]; then
    echo "Upload succeeded"
    
    SSEKMSID="$(aws s3api head-object \
            --bucket "${BUCKET_NAME}" \
            --key incoming/sample-837p-claims.csv \
            --profile "$PROFILE" \
            --no-cli-pager \
            --output text \
            --query SSEKMSKeyId 2>&1)" || true

    SERVERSIDEENCRYPTION="$(aws s3api head-object \
            --bucket "${BUCKET_NAME}" \
            --key incoming/sample-837p-claims.csv \
            --profile "$PROFILE" \
            --no-cli-pager \
            --output text \
            --query ServerSideEncryption 2>&1)" || true

    if [[ "$SERVERSIDEENCRYPTION" == *"aws:kms"* ]] && [[ "$SSEKMSID" == "$S3_KMS_KEY_ARN" ]]; then
        echo "Test 2 PASS: encrypted upload used KMS"
    else
        echo "$SERVERSIDEENCRYPTION"
        echo "$SSEKMSID"
        echo "Test 2 FAILED: encrypted upload did not use KMS"
        FAILURES+=("Test 2 FAILED - encrypted upload did not use KMS")
    fi
else
    echo "Test 2 FAILED"
    FAILURES+=("$OUTPUT")
fi



# Test 3  - download as the processing role - with both Get object and kms: decryption
CREDS=$(aws sts assume-role \
  --role-arn "${PROCESSING_ROLE_ARN}" \
  --role-session-name processing-test \
  --profile $PROFILE \
  --no-cli-pager \
  --query 'Credentials.[AccessKeyId, SecretAccessKey, SessionToken]' \
  --output text 2>&1) || true

ACCESS_KEY="$(echo "$CREDS" | cut -f1)"
SECRET_KEY="$(echo "$CREDS" | cut -f2)"
SESSION_TOKEN="$(echo "$CREDS" | cut -f3)"


if [[ -z "$ACCESS_KEY" || -z "$SECRET_KEY" || -z "$SESSION_TOKEN" ]]; then
    echo "Test 3 FAILED: unable to assume processing role, unable to retrieve credentials"
    FAILURES+=("Test 3 FAILED: unable to assume processing role, unable to retrieve credentials")
else
    export AWS_ACCESS_KEY_ID="$ACCESS_KEY"
    export AWS_SECRET_ACCESS_KEY="$SECRET_KEY"
    export AWS_SESSION_TOKEN="$SESSION_TOKEN"
    
    echo "Test 3: Assumed processing role successfully"
        
    if OUTPUT=$(aws s3 cp \
    s3://"${BUCKET_NAME}"/incoming/sample-837p-claims.csv \
    ./downloaded-by-processing.csv 2>&1) || true; then
    
    OUTPUT=$(head -3 downloaded-by-processing.csv) || true
    if [[ "$OUTPUT" == *"claim_id"* ]]; then
    echo "Test 3 PASS : downloaded file as processing role"    

    else
    echo "Test 3 FAILED: downloaded file as processing role but content is encrypted"
        FAILURES+=("Test 3 FAILED: downloaded file as processing role but content is encrypted")
        fi
    fi
fi

# clearing the environment variables after the test
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN



# test 4 - download without correct roles 





#   head -3 downloaded-by-processing.csv


# aws sts assume-role \
#   --role-arn arn:aws:iam::948285518372:role/hipaa-lab01-unauthorized-analyst \
#   --role-session-name analyst-test \
#   --profile hipaa-labs \
#   --no-cli-pager


# aws s3 cp \
#   s3://hipaa-lab01-phi-landing-948285518372/incoming/sample-837p-claims.csv \
#   ./downloaded-by-analyst.csv





#  # cloud trail look ups 
# aws cloudtrail lookup-events \
#   --lookup-attributes AttributeKey=EventName,AttributeValue=Decrypt \
#   --max-results 5 \
#   --profile $PROFILE \
#   --no-cli-pager


#   aws s3 cp \
#   s3://"${BUCKET_NAME}"/incoming/sample-837p-claims.csv \
#   ./downloaded-by-processing.csv




