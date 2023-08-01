import matplotlib.pyplot as plt
from matplotlib.legend_handler import HandlerLine2D
import numpy as np


numberOfOperations = 2000
percentileError = 99

def loadFile(filename):
	first = 0
	MyArray = np.array([])
	with open("Data/" + filename+'.txt') as my_file:
		for line in my_file:
			value = float(line.rstrip())     
			#if(value > 30):
			#	first = first +  1
			#	continue			
			MyArray = np.append( MyArray , value) #mili to sec and num of op per sec

	print(filename + " Mean:" + str(np.mean(MyArray)) + " MAx: " + str(np.max(MyArray)) + " MIn: " + str(np.min(MyArray)) )
	#print(filename + " total:" + str(np.sum(MyArray)) + " MIn: " + str(MyArray.shape) )

	return MyArray


def get_error(values):
	values.sort()
	max = np.percentile(values, percentileError)
	min = np.percentile(values, 100-percentileError)

	#max = np.max(values)
	#min = np.min(values)
	error_size = max - min
	error_y = min + error_size/2
	#print(max)
	#print(min)
	#print(error_size/2)
	#print(error_y)

	return [error_size/2, error_y]


def create_line(name, _color, _label, real_label, _marker, _linestyle):

	_label2 = _label
	_label = "_" + _label
	#TH1 = loadFile(name + str(1) + _label)
	TH2 = loadFile(name + str(2) + _label)
	TH4 = loadFile(name + str(4) + _label)
	TH8 = loadFile(name + str(8) + _label)
	TH16 = loadFile(name + str(16) + _label)
	TH32 = loadFile(name + str(32) + _label)

	#TH1_m = np.median(TH1)
	TH2_m = np.mean(TH2)
	TH4_m = np.mean(TH4)
	TH8_m = np.mean(TH8)
	TH16_m = np.mean(TH16)
	TH32_m = np.mean(TH32)
	#x = np.linspace(1.0, n_points, num=n_points


	x = [ 2, 4, 8, 16, 32]
	y = [ TH2_m, TH4_m, TH8_m, TH16_m, TH32_m]

	# Fixing random state for reproducibility


	line1, = plt.plot(x, y, marker="s",  markersize=5 , label=real_label, color= _color, linewidth= 1 , linestyle = _linestyle)

	up_yerr = [get_error(TH2)[0] ,get_error(TH4)[0], get_error(TH8)[0], get_error(TH16)[0], get_error(TH32)[0]]
	y = [get_error(TH2)[1] ,get_error(TH4)[1], get_error(TH8)[1], get_error(TH16)[1], get_error(TH32)[1]]

	plt.errorbar(x, y, yerr=up_yerr , fmt=' ', capsize=3, color = _color, linewidth= 0.7)


	return line1


# '-', '--', '-.', ':', 'None', ' ', '', 'solid', 'dashed', 'dashdot', 'dotted'

#n_points = len(OmegaSecure)


fig, ax = plt.subplots(figsize=(7, 2.5))
ax.set_xlim([0,35])
ax.set_ylim([0,4])
#line1 = create_line("run_NUC_TH", "steelblue", 'DaCOSE NO SGX')
#line1 = create_line("run_SGX_NUC_TH", "darkorange", 'DaCOSE SGX')
line1 = create_line("test_Tree", "steelblue", 'Threads1', "Verifier 1 Thread", '^', "dotted")
line2 = create_line("test_Tree", "darkorange", 'Threads2', "Verifier 2 Threads", 'd', "dashed")
#line2 = create_line("test_Tree", "darkgreen", 'Threads3')
line2 = create_line("test_Tree", "darkgreen", 'Threads4', "Verifier 4 Threads", 'x', 'solid')
#line2 = create_line("test_Tree", "steelblue", 'Threads5')
line2 = create_line("test_Tree", "darkred", 'Threads6', "Verifier 6 Threads", 's', 'dashdot')
#line2 = create_line("test_Tree", "steelblue", 'Threads7')
#line2 = create_line("test_Tree", "purple", 'Threads8', "AC 8 Threads")
#line2 = create_line("test_Tree", "steelblue", 'Threads9')
#line2 = create_line("test_Tree", "steelblue", 'Threads10')
#line2 = create_line("test_Tree", "steelblue", 'Threads11')
line2 = create_line("test_Tree", "black", 'Threads12', "Verifier 12 Threads", 'o', 'dotted')
#line2 = create_line("test_Tree", "steelblue", 'Threads13')
#line2 = create_line("test_Tree", "steelblue", 'Threads14')
#line2 = create_line("test_Tree", "steelblue", 'Threads15')
#line2 = create_line("test_Tree", "steelblue", 'Threads16')
#line2 = create_line("test_Tree", "steelblue", 'Threads32')



#line2, = plt.plot(x, TH4, marker='o', label='OmegaKV_NS') ssh intelnuc5@146.193.41.232



_fontSize = 16

lgnd =plt.legend(frameon=False, handler_map={line1: HandlerLine2D(numpoints=1)})


#as setas
#plt.annotate('Text1', xy=(32, 1.5), xytext=(32, 3.3), 
#        arrowprops=dict(alpha=0.5, fc='r', ec='r', headwidth=10))

#ax.annotate("New Year's Day", xy=(32,1.5),  xycoords='data',
#            xytext=(32,20), textcoords='offset points',
#            arrowprops=dict(arrowstyle="->",
#                            connectionstyle="arc3,rad=-0.5"))

wordSize = 8
_rotation = 60

ax.annotate("",
            xy=(32.3, 2.05), xycoords='data',
            xytext=(32.3, 3.55), textcoords='data',
            arrowprops=dict(arrowstyle="->",
                            connectionstyle="arc3,rad=-0.3"),
            )


#ax.text(33.7, 3.3, r'Improvement', fontsize=6, style='oblique', fontweight='bold', rotation=0)

ax.text(33.2, 2.7, r'x47%', fontsize=wordSize, style='oblique', fontweight='bold', rotation=_rotation)



ax.annotate("",
            xy=(32.5, 1.15), xycoords='data',
            xytext=(32.5, 1.8), textcoords='data',
            arrowprops=dict(arrowstyle="->",
                            connectionstyle="arc3,rad=-0.3"),
            )

ax.text(33.18, 1.4, r'x45%', fontsize=wordSize, style='oblique', fontweight='bold', rotation=_rotation)

ax.annotate("",
            xy=(32.5, 0.7), xycoords='data',
            xytext=(32.5, 1.1), textcoords='data',
            arrowprops=dict(arrowstyle="->",
                            connectionstyle="arc3,rad=-0.3"),
            )

ax.text(33.18, 0.8, r'x19%', fontsize=wordSize, style='oblique', fontweight='bold', rotation=_rotation)





#plt.style.use('fivethirtyeight')
#plt.grid(True)
x = [2,4, 8, 16, 32]
y = np.asarray([ "2","4","8","16","32"])
plt.xticks(x, y)

#plt.xticks(fontsize=14, rotation=90)
#plt.xticks(fontsize=15)
#plt.yticks(fontsize=15)



ax.spines['right'].set_visible(False)
ax.spines['top'].set_visible(False)

#ax.yaxis.set_ticks_position('left')
#ax.xaxis.set_ticks_position('bottom')

ax.minorticks_on()
L = 5
W = 1
ax.tick_params(which='major',  length=L, width=W, direction='inout')
ax.tick_params(which='minor',  length=4, width=W, direction='in')
ax.xaxis.set_tick_params(which='minor', bottom=False)


#ax.set_xlabel('Slot tree height = $log_{2} \frac{epoch}{\u03B4} $, percentile error of ' + str(percentileError) + "%")
ax.set_xlabel('Slot tree height = '+ r'$log_{2}\left(\frac{epoch}{\delta}\right)$, percentile error of ' + str(percentileError) + "%")

ax.set_ylabel('Request Client Latency (ms)')

fig.savefig("figure7.pdf", bbox_inches='tight')


#plt.show()























