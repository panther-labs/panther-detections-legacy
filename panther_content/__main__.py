import json
import os

from panther_detections.providers import crowdstrike, okta
from panther_detections.utils import *  # ensure utils can be imported

okta.use_all_with_defaults()
crowdstrike.use_all_with_defaults()
