#!/bin/bash

# Create priority labels
gh label create "high-priority" --color "FF0000" --description "High priority issues"
gh label create "medium-priority" --color "FFA500" --description "Medium priority issues"
gh label create "low-priority" --color "FFFF00" --description "Low priority issues"

# Create type labels
gh label create "bug" --color "D73A4A" --description "Something isn't working"
gh label create "enhancement" --color "A2EEEF" --description "New feature or request"
gh label create "documentation" --color "0075CA" --description "Documentation improvements"
gh label create "good first issue" --color "7057FF" --description "Good for newcomers"
gh label create "help wanted" --color "008672" --description "Extra attention is needed" 