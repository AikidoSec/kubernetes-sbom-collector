package service

import (
	"context"
	"fmt"

	"aikidoSec.kubernetes-sbom-collector/internal/clients/agent"
	"aikidoSec.kubernetes-sbom-collector/internal/clients/output"
	"aikidoSec.kubernetes-sbom-collector/pkg/logger"
	"aikidoSec.kubernetes-sbom-collector/pkg/models"
)

type Service struct {
	logger       *logger.Logger
	outputClient *output.Client
	agentClient  *agent.Client
}

func NewService(logger *logger.Logger, outputClient *output.Client, agentClient *agent.Client) *Service {
	return &Service{
		logger:       logger,
		outputClient: outputClient,
		agentClient:  agentClient,
	}
}

func (s *Service) GetImageStatus(ctx context.Context, image, digest string) (models.ImageStatus, error) {
	imageStatus, err := s.agentClient.GetImageStatus(ctx, image, digest)
	if err != nil {
		return models.ImageStatus{}, fmt.Errorf("error getting image status: %w", err)
	}
	return imageStatus, nil
}

func (s *Service) MarkProcessedImage(ctx context.Context, image, digest string) error {
	imgStatus := models.ImageStatus{
		Image:       image,
		Digest:      digest,
		IsProcessed: true,
	}

	if err := s.agentClient.SetImageStatus(ctx, imgStatus); err != nil {
		return fmt.Errorf("error setting image status: %w", err)
	}
	return nil
}

func (s *Service) SendImageSBOM(ctx context.Context, payload models.SBOMPayload) error {
	apiToken, err := s.agentClient.GetAPIToken(ctx)
	if err != nil {
		return fmt.Errorf("error getting API token: %w", err)
	}

	if err := s.outputClient.SendSBOM(ctx, payload, apiToken.Token); err != nil {
		return fmt.Errorf("error sending SBOM: %w", err)
	}

	if err := s.MarkProcessedImage(ctx, payload.Image, payload.Digest); err != nil {
		return fmt.Errorf("error marking image as processed: %w", err)
	}

	return nil
}
