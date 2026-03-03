package targets

import (
	"isnan.eu/alerting/cmd/models"
)

type Target interface {
	GetName() string
	SendAlert(alert *models.AlertMessage) error
}
