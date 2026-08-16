# --- paperloop ---
.PHONY: gate loop loop-dry render
gate:            ## measure the manuscript against USENIX Security 2027
	python3 .paperloop/run_gates.py --build --render
loop:            ## run the self-correcting loop end to end
	python3 .paperloop/loop.py --rounds 6 --push --pr
loop-dry:        ## one measured round, no edits, writes the work order
	python3 .paperloop/loop.py --rounds 1 --gates-only
render:          ## export page images for visual QA
	python3 .paperloop/checks/check_figures.py . --render
