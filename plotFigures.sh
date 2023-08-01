#!/usr/bin/env bash

cd PlotFigures/Figure7/
python3 CreateFigure.py
cd ../../


cd PlotFigures/Figure8/
python3 CreateFigure.py
cd ../../



cd PlotFigures/Figure9/
python3 CreateFigure.py
cd ../../

wait
echo ""
echo "--- Figures completed ---"

