resource "aws_kms_key" "statement_signing" {
  description              = "Signs monthly account statements"
  customer_master_key_spec = "RSA_2048"
  key_usage                = "SIGN_VERIFY"
}

resource "google_kms_crypto_key" "device_attestation" {
  name     = "device-attestation"
  key_ring = "projects/identity/locations/asia-south1/keyRings/devices"
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm = "EC_SIGN_P256_SHA256"
  }
}
