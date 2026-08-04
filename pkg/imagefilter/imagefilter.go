package imagefilter

import (
	"fmt"

	"github.com/gobwas/glob"
)

type NamePatterns []glob.Glob

// CompileNamePatterns compiles image name patterns once so they can be reused while processing images.
func CompileNamePatterns(patterns []string) (NamePatterns, error) {
	compiledPatterns := make(NamePatterns, 0, len(patterns))
	for _, pattern := range patterns {
		compiled, err := glob.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("error compiling image name pattern %q: %w", pattern, err)
		}

		compiledPatterns = append(compiledPatterns, compiled)
	}

	return compiledPatterns, nil
}

func (p NamePatterns) Match(imageName string) bool {
	for _, pattern := range p {
		if pattern.Match(imageName) {
			return true
		}
	}

	return false
}
