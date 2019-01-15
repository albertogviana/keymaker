package api

// ErrorResponse describes an error
type ErrorResponse struct {
	Error ErrorService `json:"error"`
}

// ErrorService returns the details of an error
type ErrorService struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}
