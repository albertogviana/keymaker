package certificate

type Certificate struct {
	*Config
}

type Config struct {
}

func NewCertificate() *Certificate {
	return &Certificate{}
}
