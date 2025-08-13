import logging

from .importer import SnykApiImporter

logger = logging.getLogger(__name__)


class SnykApiUpdaterFromSource:

    """
    The responsibility of this class is to update the Finding status if current Snyk issue status doesn't match.
    
    Note: Snyk API has limited capabilities for status updates compared to SonarQube.
    This is a placeholder for future functionality.
    """

    def update(self, finding):
        """
        Update DefectDojo finding based on Snyk issue status.
        Note: Snyk API currently has limited support for status updates.
        This method is a placeholder for future implementation.
        """
        logger.info(f"Snyk issue status updates are not currently supported for finding '{finding}'")
        # Future implementation would go here when Snyk API supports more status operations
        pass
