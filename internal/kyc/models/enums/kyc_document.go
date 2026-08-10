package enums

// DocumentType defines the type of KYC document
type DocumentType string

const (
	DocumentTypeIdentity DocumentType = "identity"
	DocumentTypeAddress  DocumentType = "address"
	DocumentTypeBusiness DocumentType = "business"
	DocumentTypeSelfie   DocumentType = "selfie"
)

func (dt DocumentType) IsValid() bool {
	switch dt {
	case DocumentTypeIdentity, DocumentTypeAddress, DocumentTypeBusiness, DocumentTypeSelfie:
		return true
	default:
		return false
	}
}

// DocumentUploadStatus represents the verification status of a document
type DocumentUploadStatus string

const (
	DocumentStatusPending  DocumentUploadStatus = "pending"
	DocumentStatusUploaded DocumentUploadStatus = "uploaded"
	DocumentStatusVerified DocumentUploadStatus = "verified"
	DocumentStatusRejected DocumentUploadStatus = "rejected"
)

func (us DocumentUploadStatus) IsValid() bool {
	switch us {
	case DocumentStatusPending, DocumentStatusUploaded, DocumentStatusVerified, DocumentStatusRejected:
		return true
	default:
		return false
	}
}
