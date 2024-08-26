#!/usr/bin/env bats

@test "accept when no settings are provided" {
  run kwctl run annotated-policy.wasm -r test_data/ingress.json

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request accepted
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}

@test "accept user defined constraint is respected" {
  run kwctl run annotated-policy.wasm \
    -r test_data/ingress.json \
    --settings-json '{"constrained_annotations": {"owner": "^team-"}}'
  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request accepted
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}

@test "accept annotations are not on deny list" {
  run kwctl run  annotated-policy.wasm \
    -r test_data/ingress.json \
    --settings-json '{"denied_annotations": ["foo", "bar"]}'
  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request accepted
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}

@test "reject because annotation is on deny list" {
  run kwctl run annotated-policy.wasm \
    -r test_data/ingress.json --settings-json '{"denied_annotations": ["foo", "owner"]}'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request rejected
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
  [ $(expr "$output" : '.*The following annotations are not allowed: owner.*') -ne 0 ]
}

@test "reject because annotation doesn't pass validation constraint" {
  run kwctl run annotated-policy.wasm \
    -r test_data/ingress.json \
    --settings-json '{"constrained_annotations": {"cc-center": "^cc-\\d+$"}}'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request rejected
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
  [ $(expr "$output" : ".*The following annotations are violating user constraints: cc-center.*") -ne 0 ]
}

@test "reject because a required annotation does not exist" {
  run kwctl run policy.wasm \
    -r test_data/ingress.json --settings-json '{"mandatory_annotations": ["required"], "constrained_annotations": {"foo": ".*"}}'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request rejected
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
  [ $(expr "$output" : '.*The following mandatory annotations are missing: required.*') -ne 0 ]
}

@test "fail settings validation because constrained annnotations are also denied" {
  run kwctl run policy.wasm \
    -r test_data/ingress.json \
    --settings-json '{"denied_annotations": ["foo", "cc-center"], "constrained_annotations": {"cc-center": "^cc-\\d+$"}}'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # settings validation fails
  [ "$status" -eq 1 ]
  [ $(expr "$output" : ".*Provided settings are not valid: These annotations cannot be constrained and denied at the same time: cc-center.*") -ne 0 ]
}

@test "fail settings validation because mandatory annotations are also denied" {
  run kwctl run policy.wasm \
    -r test_data/ingress.json \
    --settings-json '{"denied_annotations": ["foo", "cc-center"], "mandatory_annotations": ["cc-center"]}'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # settings validation fails
  [ "$status" -eq 1 ]
  [ $(expr "$output" : ".*Provided settings are not valid: These annotations cannot be mandatory and denied at the same time: cc-center.*") -ne 0 ]
}

@test "fail settings validation because of invalid constraint" {
  run kwctl run annotated-policy.wasm \
    -r test_data/ingress.json \
    --settings-json '{"constrained_annotations": {"cc-center": "^cc-[12$"}}'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # settings validation fails
  [ "$status" -eq 1 ]
  [ $(expr "$output" : ".*Provided settings are not valid: error parsing regexp: missing closing.*") -ne 0 ]
}
