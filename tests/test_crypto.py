from magicproxy.config import Config
from magicproxy.crypto import generate_keys
from OpenSSL import crypto, SSL

DEFAULT_PRIVATE_KEY_LOCATION = "keys/private.pem"
DEFAULT_PUBLIC_KEY_LOCATION = "keys/public.pem"
DEFAULT_PUBLIC_CERTIFICATE_LOCATION = "keys/public.x509.cer"


def test_generate_keys(tmp_path):
    public_key_location = tmp_path / "public.pem"
    private_key_location = tmp_path / "private.pem"
    public_certificate_location = tmp_path / "public.x509.cer"

    config = Config(
        public_key_location=public_key_location,
        private_key_location=private_key_location,
        public_certificate_location=public_certificate_location,
    )
    generate_keys(config)

    assert public_key_location.exists()
    assert private_key_location.exists()
    assert public_certificate_location.exists()

    assert "-----BEGIN PUBLIC KEY-----" in public_key_location.read_text()
    assert "-----BEGIN PRIVATE KEY-----" in private_key_location.read_text()
    assert "-----BEGIN CERTIFICATE-----" in public_certificate_location.read_text()

    public_key = crypto.load_publickey(
        crypto.FILETYPE_PEM, public_key_location.read_bytes()
    )
    private_key = crypto.load_privatekey(
        crypto.FILETYPE_PEM, private_key_location.read_bytes()
    )
    certificate = crypto.load_certificate(
        crypto.FILETYPE_PEM, public_certificate_location.read_bytes()
    )

    assert crypto.dump_publickey(
        crypto.FILETYPE_ASN1, private_key
    ) == crypto.dump_publickey(crypto.FILETYPE_ASN1, public_key)

    context = SSL.Context(SSL.TLSv1_METHOD)
    context.use_privatekey(private_key)
    context.use_certificate(certificate)

    context.check_privatekey()
