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

func (s *Service) IsImageProcessed(ctx context.Context, image, imageSHA string) (bool, error) {
	imageStatus, err := s.agentClient.GetImageStatus(ctx, fmt.Sprintf("%s:%s", image, imageSHA))
	if err != nil {
		return false, fmt.Errorf("error getting image status: %w", err)
	}
	return imageStatus.IsProcessed, nil
}

func (s *Service) MarkProcessedImage(ctx context.Context, image, imageSHA string) error {
	imgStatus := models.ImageStatus{
		Image:       fmt.Sprintf("%s:%s", image, imageSHA),
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

	if err := s.MarkProcessedImage(ctx, payload.Image, payload.ImageSHA); err != nil {
		return fmt.Errorf("error marking image as processed: %w", err)
	}
	
	return nil
}
