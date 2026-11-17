package service

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"aikidoSec.kubernetes-sbom-collector/internal/clients/agent"
	"aikidoSec.kubernetes-sbom-collector/internal/clients/output"
	"aikidoSec.kubernetes-sbom-collector/pkg/logger"
	"aikidoSec.kubernetes-sbom-collector/pkg/models"
)

type Service struct {
	logger                *logger.Logger
	outputClient          *output.Client
	agentClient           *agent.Client
	sbomRequestRetryDelay time.Duration
}

func NewService(logger *logger.Logger, outputClient *output.Client, agentClient *agent.Client, sbomRequestRetryDelay time.Duration) *Service {
	return &Service{
		logger:                logger,
		outputClient:          outputClient,
		agentClient:           agentClient,
		sbomRequestRetryDelay: sbomRequestRetryDelay,
	}
}

func (s *Service) GetImageStatus(ctx context.Context, image, digest, architecture string) (models.ImageStatus, error) {
	imageStatus, err := s.agentClient.GetImageStatus(ctx, image, digest, architecture)
	if err != nil {
		return models.ImageStatus{}, fmt.Errorf("error getting image status: %w", err)
	}
	return imageStatus, nil
}

func (s *Service) MarkProcessedImage(ctx context.Context, image, digest, architecture string) error {
	imgStatus := models.ImageStatus{
		Image:        image,
		Digest:       digest,
		Architecture: architecture,
		IsProcessed:  true,
	}

	if err := s.agentClient.SetImageStatus(ctx, imgStatus); err != nil {
		return fmt.Errorf("error setting image status: %w", err)
	}
	return nil
}

func (s *Service) SendImageSBOM(ctx context.Context, sbomPayload models.SBOMPayload) error {
	sbomJSON, err := json.Marshal(sbomPayload)
	if err != nil {
		return fmt.Errorf("could not marshal SBOM payload: %w", err)
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(sbomJSON); err != nil {
		return fmt.Errorf("could not gzip SBOM payload: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("could not gzip SBOM payload: %w", err)
	}

	for {
		apiToken, err := s.agentClient.GetAPIToken(ctx)
		if err != nil {
			return fmt.Errorf("error getting API token: %w", err)
		}

		if err := s.outputClient.SendSBOM(ctx, buf.Bytes(), apiToken.Token); err != nil {
			s.logger.LogWarning(err, "unable to send SBOM, request will be retried after delay")
			time.Sleep(s.sbomRequestRetryDelay)
			continue
		}

		if err := s.MarkProcessedImage(ctx, sbomPayload.Image, sbomPayload.Digest, sbomPayload.Architecture); err != nil {
			return fmt.Errorf("error marking image as processed: %w", err)
		}

		return nil
	}
}
