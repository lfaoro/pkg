tag?=""
tag:
	git tag -f -a $(tag) -m "$(tag)"
	git push -f origin $(tag)