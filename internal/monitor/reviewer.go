//go:build !monitor_dev

package monitor

import "context"

// Automated review fields and execution are absent from release records.
type developmentRecordFields struct{}
type developmentRecordSummaryFields struct{}

func assignDevelopmentReviewer(*settings, *record, string)         {}
func (m *monitor) startDevelopmentReview(context.Context, *record) {}
func copyDevelopmentReviewSummary(*record, *recordSummary)         {}
