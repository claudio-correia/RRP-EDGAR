import numpy as np
import matplotlib.pyplot as plt
from matplotlib.ticker import (MultipleLocator, AutoMinorLocator)
from matplotlib.ticker import FixedLocator, FixedFormatter

# set width of bar
barWidth = 0.13
fig, ax = plt.subplots(figsize =(7.5, 2.5))



midle_points = np.array([])	

x_curve_points = np.array([])	
y_curve_points = np.array([])	




ax2=ax.twinx()
ax2.set_ylim([0,7400])
ax.set_ylim([0,74])


def loadFile(filename, N_value):
	first = 0
	n_loop_in_server = 0;
	MyArray = np.array([])
	with open("Data/" + filename+'.txt') as my_file:
		for line in my_file:
			value = float(line.rstrip())     
			if(first == 0):
				first = first +  1
				n_loop_in_server = value
				continue			
			MyArray = np.append( MyArray , value) #mili to sec and num of op per sec

	#print(filename + " total:" + str(np.sum(MyArray)) + " MIn: " + str(MyArray.shape) )


	mean = np.mean( MyArray )
	mean_s = mean/1000

	throughput =  (n_loop_in_server*N_value)/mean_s
	
	#print(filename + " throughput: "+ str(throughput) + " Mean:" + str(np.mean(MyArray)) + " MAx: " + str(np.max(MyArray)) + " MIn: " + str(np.min(MyArray)) )


	return throughput

def get_mean_bar(N_value, max_TS, append_sgx): #para calcular a soma das medias de cada thread do server

	x = 0
	MeanArray = np.array([])	

	while x < max_TS:
		filename = append_sgx + "TS_" + str(max_TS) +"_N_" + str(N_value) + "_thread_" + str(x) 
		MeanArray = np.append(MeanArray, loadFile( filename , N_value) )
		x = x + 1

	print(filename + " throughput: "+ str(np.sum(MeanArray)) + " MAx: " + str(np.max(MeanArray)) + " MIn: " + str(np.min(MeanArray)) )
	
	return np.sum(MeanArray)

def make_bars(bars0, bars1, bars2, last_point):
	global x_curve_points, y_curve_points, midle_points, no_line

	# Set position of bar on X axis
	br1 = last_point + np.arange(len(bars1))/2
	br2 = [x + barWidth for x in br1]
	br3 = [x + barWidth for x in br2]

	
	divide_points = [1,1,1]
	for x in range(len(bars1)):
		#x_curve_points = np.append( x_curve_points , br1[x])
		x_curve_points = np.append( x_curve_points , br2[x])
		#x_curve_points = np.append( x_curve_points , br3[x])

		#y_curve_points = np.append( y_curve_points , bars0[x])
		y_curve_points = np.append( y_curve_points , bars1[x])
		#y_curve_points = np.append( y_curve_points , bars2[x])
	
		#divide_points =  np.multiply(divide_points,2)
		#y_curve_points = np.divide(y_curve_points, divide_points)
		#ax2.plot(x_curve_points, y_curve_points,color ='#ff383f', marker='o',markersize=3, linestyle='--',  linewidth = 1);
		#
		#x_curve_points = np.array([])	
		#y_curve_points = np.array([])	


	#print(br1)
	midle_points = np.append( midle_points , br1)


	#print( "bars1: " + str(bars1) )
	#print( "br1: " +  str(br1) )
	#print( "bars2: " +  str(bars2) )
	#print( "br2: " +  str(br2) )

	bars0 = bars0/1000
	bars1 = bars1/1000
	bars2 = bars2/1000


	# Make the plot
	ax.bar(br1, bars0, color ='mediumaquamarine', width = barWidth)	
	ax.bar(br2, bars1, color ='darkgreen', width = barWidth )
	ax.bar(br3, bars2, color ='#5b62ff', width = barWidth)

	# Adding Xticks
	#plt.xlabel('IS 1 Thread', fontweight ='bold', fontsize = 15)
	#plt.xlabel('IS 1 Thread')
	#ax.ylabel('Throughput (K Pseudonyms/s)')
	r = last_point
	#plt.xticks([r + barWidth/2 for r in range(len(IT))],
	#		['1N', '2N', '3N', '4N', '5N'])


	#plt.xticks(br1 + barWidth/2,
	#		['1N', '2N', '3N', '4N', '5N'])


	if(no_line == 0):
		plt.axvline(x=max(br2) + barWidth*2.5, linestyle=':',  linewidth = 1, color='black')

	return max(br2) + barWidth*4


def laod_and_make_line(Number_of_server_threads, last_point, first_point, final_point):
	global x_curve_points, y_curve_points

	x = first_point
	MyArrayNoSGXORLP = np.array([])	
	while x <= final_point:
		append_sgx = "ORLP_SGX_"	
		MyArrayNoSGXORLP = np.append(MyArrayNoSGXORLP,  get_mean_bar(x, Number_of_server_threads, append_sgx)) 
		x = x*2

	x = first_point
	MyArrayNoSGXSSL = np.array([])	
	while x <= final_point:
		MyArrayNoSGXSSL = np.append(MyArrayNoSGXSSL,  get_mean_bar(x, Number_of_server_threads, "SSL_")) 
		x = x*2

	x = first_point
	MyArrayWithSGXSSL = np.array([])
	while x <= final_point:
		append_sgx = "SSL_SGX_"
		MyArrayWithSGXSSL = np.append(MyArrayWithSGXSSL, get_mean_bar(x, Number_of_server_threads, append_sgx)) 
		x = x*2

	last_point = make_bars(MyArrayNoSGXORLP, MyArrayWithSGXSSL, MyArrayNoSGXSSL, last_point)

	
	#divide_points = [2,2,2,4,4,4,8,8,8,16,16,16,32,32,32]
	divide_points = [4,8,16,32]
	y_curve_points = np.divide(y_curve_points, divide_points)
	ax2.plot(x_curve_points, y_curve_points,color ='#ff383f', marker='o',markersize=3, linestyle='--',  linewidth = 1);
	
	x_curve_points = np.array([])	
	y_curve_points = np.array([])	

	return last_point







no_line = 0
last_point = 0

last_point = laod_and_make_line(1, last_point, 4, 36)
last_point = laod_and_make_line(2, last_point, 4, 36)
last_point = laod_and_make_line(4, last_point, 4, 36)
no_line = 1
last_point = laod_and_make_line(6, last_point, 4, 36)
#last_point = laod_and_make_line(12, last_point, 2, 36)





#divide_points = [2,2,2,4,4,4,8,8,8,16,16,16,32,32,32,2,2,2,4,4,4,8,8,8,16,16,16,32,32,32,2,2,2,4,4,4,8,8,8,16,16,16,32,32,32,2,2,2,4,4,4,8,8,8,16,16,16,32,32,32]
#y_curve_points = np.divide(y_curve_points, divide_points)
#ax2.plot(x_curve_points, y_curve_points,color ='#ff383f', marker='o',markersize=3, linestyle='--',  linewidth = 1);


#divide_points = [2,2,2,4,4,4,8,8,8,16,16,16,32,32,32,2,2,2,4,4,4,8,8,8,16,16,16,32,32,32,2,2,2,4,4,4,8,8,8,16,16,16,32,32,32,2,2,2,4,4,4,8,8,8,16,16,16,32,32,32]
#y_curve_points = np.divide(y_curve_points, divide_points)







p1, = plt.bar(0, 0, color ='mediumaquamarine')
p2, = plt.bar(0, 0, color ='darkgreen')
p3, = plt.bar(0, 0, color ='#5b62ff')
p4, = plt.plot(-10, 0,color ='#ff383f', marker='o',markersize=3, linestyle='--',  linewidth = 1);
#plt.legend( [p1, p2, p3, p4], ['Throughput W/SGX Ed25519 portable', 'Throughput W/SGX openSSL', 'Throughput W/o SGX openSSL', '# of Served Clients (W/SGX openSSL)'], loc=2, ncol=2, bbox_to_anchor=(-0.1,1.2), frameon=False)
plt.legend( [p1, p2, p3, p4], ['Throughput Ed25519 portable W/SGX', 'Throughput OpenSSL W/SGX', 'Throughput OpenSSL W/o SGX', '# of Served Clients (OpenSSL W/SGX)'], loc=2, ncol=2, bbox_to_anchor=(-0.1,1.3), frameon=False)






plt.xlim([-(barWidth*2), 8.47])

print(midle_points)

#midle_points = [0, 0.5, 1,  1.5, 2, 2.65, 3.15, 3.65, 4.15, 4.65 ]
#midle_points = [0, 0.5, 1, 1.01, 1.5, 2, 2.65, 3.15, 3.65, 3.6501, 4.15, 4.65 ]
#
##midle_points = [0, 0.5, 1, 1.01, 1.5, 2, 2.65, 3.15, 3.65, 3.6501, 4.15, 4.65, 5.3, 5.8, 6.3, 6.301, 6.8, 7.3, 7.95, 8.45, 8.95, 8.9501, 9.45, 9.95]
#midle_points = [0, 0.5, 0.75, 1, 1.5, 2.15, 2.65, 2.9, 3.15, 3.65, 4.3, 4.8, 5.05, 5.3, 5.8, 6.45, 6.95, 7.2, 7.45, 7.95]
#
#midle_points = [x + barWidth for x in midle_points]
#plt.xticks(midle_points,
#			[ '4N', '8N', "\nIS 1 Thread" , '16N', '32N', '4N', '8N', "\nIS 2 Threads", '16N', '32N', '4N', '8N', "\nIS 4 Threads", '16N', '32N', '4N', '8N', "\nIS 6 Threads", '16N', '32N'])

#x_ticks = [0,  0.5, 1,   1.5,  2.15, 2.65, 3.15, 3.65, 4.3,  4.8,  5.3,  5.8,  6.45, 6.95, 7.45, 7.95]
#plt.set_xticks(x_ticks)
#xticks = ax.xaxis.get_major_ticks()
#xticks[1].label1.set_visible(False)



#ax2.set_yticks([0, 2000, 4000, 6000, 8000 ])
#ax2.set_yticklabels( ["0", '$2x10^{3}$', "4000", "6000", "8000" ])

#plt.yscale('log', nonposy='clip')


#plt.xticks([0, 0.5,  1,  1.5, 2, 2.65, 3.15, 3.65, 4.15, 4.65 ] + barWidth,
#			['1N', '2N', '3N', '4N', '5N', '1N', '2N', '3N', '4N', '5N'])

#plt.plot(0, 0, color ='darkgreen',  label ='Throughput W/SGX')
#plt.plot(0, 0, color ='mediumaquamarine',  label ='Throughput W/o SGX')



ax.minorticks_on()
L = 5
W = 1
ax.tick_params(which='major',  length=L, width=W, direction='inout')
ax.tick_params(which='minor',  length=4, width=W, direction='in', pad =6)

#ax2.tick_params(which='major',  length=4, width=W, direction='in', pad=20)

ax.xaxis.set_tick_params(which='minor', bottom=False)
#ax.set_xticks([0.2]) 


midle_points = np.add([0, 0.5, 1, 1.5, 2.15, 2.65, 3.15, 3.65, 4.3, 4.8, 5.3, 5.8, 6.45, 6.95, 7.45, 7.95], barWidth)

#x_formatter = FixedFormatter([ '4$N^p$', '8$N^p$' , '16$N^p$', '32N', '4N', '8N', '16N', '32N', '4N', '8N', '16N', '32N', '4N', '8N', '16N', '32N'] )
x_formatter = FixedFormatter([ '4P', '8P' , '16P', '32P', '4P', '8P', '16P', '32P', '4P', '8P', '16P', '32P', '4P', '8P', '16P', '32P'] )
#x_formatter = FixedFormatter([ '4$N^p$', '8$N^p$' , '16$N^p$', '32$N^p$', '4$N^p$', '8$N^p$', '16$N^p$', '32$N^p$', '4$N^p$', '8$N^p$', '16$N^p$', '32$N^p$', '4$N^p$', '8$N^p$', '16$N^p$', '32$N^p$'] )
x_locator = FixedLocator(midle_points)

ax2.xaxis.set_major_formatter(x_formatter)
ax2.xaxis.set_major_locator(x_locator)

ax2.minorticks_on()

x_minor_formatter = FixedFormatter([
    "\nPM 1 Thread", "\nPM 2 Threads", "\nPM 4 Threads", "\nPM 6 Threads"])

new_midle_points = np.add([0.75, 2.9, 5.05, 7.2], barWidth)
x_minor_locator = FixedLocator(new_midle_points)

ax2.xaxis.set_minor_formatter(x_minor_formatter)
ax2.xaxis.set_minor_locator(x_minor_locator)

#plt.xticks(midle_points,
#			[ '4N', '8N', "\nIS 1 Thread" , '16N', '32N', '4N', '8N', "\nIS 2 Threads", '16N', '32N', '4N', '8N', "\nIS 4 Threads", '16N', '32N', '4N', '8N', "\nIS 6 Threads", '16N', '32N'])





#ax2.yaxis.set_minor_locator(AutoMinorLocator())
#ax2.set_yticks([500, 1000, 1500, 2500,3000,3500, 4500, 5000, 5500, 6500, 7000, 7500],      minor=True)
#ax2.minorticks_on()


ax2.tick_params(which='major',  length=L, width=W, direction='inout')
ax2.tick_params(which='minor',  length=4, width=W, direction='in')
#ax2.xaxis.set_tick_params(which='minor', bottom=False)
#ax2.yaxis.set_ticks(np.arange(0, 8000, 1000))



#plt.plot(color ='indianred', marker='o',markersize=3, linestyle='--',  linewidth = 1,  label ='# of Served Clients');
ax2.set_ylabel("# of Served Clients", rotation=270)
#ax2.yaxis.set_label_coords(1.06, 0.2)
ax2.yaxis.set_label_coords(1.11, 0.5)
#ax2.yticks(rotation=90)

ax.set_ylabel('Throughput (K Pseudonyms/s)')

#plt.legend(loc=2)
#ax.legend(loc=2,ncol=2, bbox_to_anchor=(0,1.2))

plt.savefig("figure8.pdf", bbox_inches='tight')


plt.legend()
#plt.show()




























