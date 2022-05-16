package trivy

import (
	"context"
	"time"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/image"
	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"

	// "github.com/aquasecurity/trivy/internal/operation"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils"
	"github.com/aquasecurity/trivy/pkg/vulnerability"

	"github.com/aquasecurity/fanal/applier"
	image2 "github.com/aquasecurity/fanal/artifact/image"
	fTypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/detector/library"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg"
	"github.com/aquasecurity/trivy/pkg/scanner/local"
)

type Trivy struct {
	imageName    string
	Results      report.Results
	Packages     []fTypes.Package
	Applications []fTypes.Application
}

func NewTrivy(name string) *Trivy {
	trivy := Trivy{imageName: name}
	return &trivy
}

func (t *Trivy) Scan() error {
	log.InitLogger(false, true)

	// configure cache dir
	cacheDir := utils.DefaultCacheDir()
	// log.Logger.Debugf("cacheDir: %s", cacheDir)
	utils.SetCacheDir(cacheDir)
	cacheClient, err := cache.NewFSCache(cacheDir)
	if err != nil {
		return xerrors.Errorf("unable to initialize the cache: %w", err)
	}
	defer cacheClient.Close()

	// download the database file
	// noProgress := false
	// appVersion := "dev"
	// light := false
	// skipUpdate := false
	// if err = operation.DownloadDB(appVersion, cacheDir, noProgress, light, skipUpdate); err != nil {
	// 	return err
	// }

	if err = db.Init(cacheDir); err != nil {
		return xerrors.Errorf("error in vulnerability DB initialize: %w", err)
	}
	defer db.Close()

	target := t.imageName

	ctx := context.Background()
	timeout := time.Second * 120
	dockerImage, cleanup, err := getDockerImage(ctx, target, timeout)
	if err != nil {
		return xerrors.Errorf("unable to initialize a dockerImage: %w", err)
	}
	defer cleanup()
	scanner, err := initializeDockerScanner(ctx, dockerImage, cacheClient, cacheClient)
	if err != nil {
		return xerrors.Errorf("unable to initialize a scanner: %w", err)
	}

	scanOptions := types.ScanOptions{
		VulnType:            []string{"os", "library"},
		ScanRemovedPackages: false, // this is valid only for image subcommand
	}
	log.Logger.Debugf("Vulnerability type:  %s", scanOptions.VulnType)

	results, err := scanner.ScanArtifact(ctx, scanOptions)
	if err != nil {
		return xerrors.Errorf("error in image scan: %w", err)
	}

	config := db.Config{}
	var severities []dbTypes.Severity
	for _, s := range dbTypes.SeverityNames {
		severity, err := dbTypes.NewSeverity(s)
		if err != nil {
			log.Logger.Warnf("unknown severity option: %s", err)
		}
		severities = append(severities, severity)
	}
	vulnClient := vulnerability.NewClient(config)
	ignoreUnfixed := false
	for i := range results {
		vulnClient.FillInfo(results[i].Vulnerabilities, results[i].Type)
		results[i].Vulnerabilities = vulnClient.Filter(results[i].Vulnerabilities, severities, ignoreUnfixed, vulnerability.DefaultIgnoreFile)
	}
	t.Results = results
	t.Packages = getPackages(ctx, dockerImage, cacheClient, cacheClient)
	t.Applications = getLibraries(ctx, dockerImage, cacheClient, cacheClient)

	return nil
}

func (t *Trivy) GetResults() report.Results {
	return t.Results
}

func (t *Trivy) GetTotalPackages() int {
	return len(t.Packages)
}

func (t *Trivy) GetTotalLibraries() int {
	count := 0
	for _, app := range t.Applications {
		count += len(app.Libraries)
	}
	return count
}

func (t *Trivy) GetTotalErrors() int {
	err_list := make([]string, 0)
	for _, result := range t.Results {
		for _, vul := range result.Vulnerabilities {
			if !contains(err_list, vul.PkgName) && (vul.Severity == "CRITICAL" || vul.Severity == "HIGH") {
				err_list = append(err_list, vul.PkgName)
			}
		}
	}
	return len(err_list)
}

// Uitility Functions

func initializeDockerScanner(ctx context.Context, dockerImage image.Image, artifactCache cache.ArtifactCache, localArtifactCache cache.LocalArtifactCache) (scanner.Scanner, error) {
	applierApplier := applier.NewApplier(localArtifactCache)
	detector := ospkg.Detector{}
	driverFactory := library.DriverFactory{}
	libraryDetector := library.NewDetector(driverFactory)
	localScanner := local.NewScanner(applierApplier, detector, libraryDetector)
	// dockerOption, err := types.GetDockerOption(timeout)
	// if err != nil {
	// 	return scanner.Scanner{}, nil, err
	// }
	// imageImage, cleanup, err := image.NewDockerImage(ctx, imageName, dockerOption)
	// if err != nil {
	// 	return scanner.Scanner{}, nil, err
	// }
	artifact := image2.NewArtifact(dockerImage, artifactCache)
	scannerScanner := scanner.NewScanner(localScanner, artifact)
	return scannerScanner, nil
}

func getDockerImage(ctx context.Context, imageName string, timeout time.Duration) (image.Image, func(), error) {
	dockerOption, err := types.GetDockerOption(timeout)
	if err != nil {
		return image.Image{}, nil, err
	}
	imageImage, cleanup, err := image.NewDockerImage(ctx, imageName, dockerOption)
	return imageImage, cleanup, err
}

func getImageDetails(ctx context.Context, dockerImage image.Image, artifactCache cache.ArtifactCache, localArtifactCache cache.LocalArtifactCache) (fTypes.ArtifactDetail, error) {
	applierApplier := applier.NewApplier(localArtifactCache)
	// dockerOption, err := types.GetDockerOption(timeout)
	// if err != nil {
	// 	return nil, nil, err
	// }
	// imageImage, cleanup, err := image.NewDockerImage(ctx, imageName, dockerOption)
	// if err != nil {
	// 	return nil, nil, err
	// }
	// defer cleanup()
	artifact := image2.NewArtifact(dockerImage, artifactCache)
	artifactInfo, _ := artifact.Inspect(ctx)
	imageDetail, err := applierApplier.ApplyLayers(artifactInfo.ID, artifactInfo.BlobIDs)
	return imageDetail, err
}

func getPackages(ctx context.Context, dockerImage image.Image, artifactCache cache.ArtifactCache, localArtifactCache cache.LocalArtifactCache) []fTypes.Package {
	imageDetail, err := getImageDetails(ctx, dockerImage, artifactCache, localArtifactCache)
	if err != nil {
		return nil
	}
	// fmt.Println("---------------------------------------------")
	// fmt.Println("OS Packages")
	// for _, pkg := range imageDetail.Packages {
	// 	fmt.Println("Name: " + pkg.Name)
	// }
	// fmt.Println("---------------------------------------------")
	return imageDetail.Packages
}

func getLibraries(ctx context.Context, dockerImage image.Image, artifactCache cache.ArtifactCache, localArtifactCache cache.LocalArtifactCache) []fTypes.Application {
	imageDetail, err := getImageDetails(ctx, dockerImage, artifactCache, localArtifactCache)
	if err != nil {
		return nil
	}
	// count := 0
	// for _, app := range imageDetail.Applications {
	// 	fmt.Println("---------------------------------------------")
	// 	fmt.Println("Type: " + app.Type)
	// 	fmt.Println("FilePath: " + app.FilePath)
	// 	for _, lib := range app.Libraries {
	// 		fmt.Println("Name: " + lib.Library.Name)
	// 	}
	// 	fmt.Println("---------------------------------------------")
	// }

	// for _, app := range imageDetail.Applications {
	// 	count += len(app.Libraries)
	// }
	return imageDetail.Applications
}

func contains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
