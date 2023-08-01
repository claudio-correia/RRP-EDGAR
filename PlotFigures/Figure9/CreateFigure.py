# Import the necessary packages and modules
import matplotlib.pyplot as plt
import numpy as np
import math
from math import e
import matplotlib.ticker as tck

#fig,ax = plt.subplots(2)
fig,ax = plt.subplots(2,figsize =(6.8, 4))
plt.subplots_adjust(hspace = .1)


#fig = plt.figure()
#gs = fig.add_gridspec(2, hspace=0.1)
#ax = gs.subplots(sharex=True, sharey=True)

#fig.tight_layout()


c = 448


def old_bf_formula(insertions):
	return ( (insertions * (math.log(1000) ))/(  math.log(2,e)*math.log(2,e)  ) ) #*0.000125# / 8000 #bf size for FP = 0.1%. A divisao por 8000 é para passar bits para KB

def bf_formula(n):
	p = 0.001

	m = math.ceil((n * math.log(p)) / math.log(1 / math.pow(2, math.log(2))))
	k = math.ceil((m / n) * math.log(2))
	
	return m*0.000125# / 8000 #bf size for FP = 0.1%. A divisao por 8000 é para passar bits para KB

def haas_calculation(x_ticks, min_pseudo_requeired, time_interval,f, p, pseudos):

	user_pseud = np.zeros(len(x_ticks))
	BF_insertions = np.zeros(len(x_ticks))
	Y_array = np.zeros(len(x_ticks))


	for i in range(len(x_ticks)):
		user_pseud[i] = (time_interval/x_ticks[i])*(min_pseudo_requeired[i] + 0) #em vez de usar o P uso mais 1 acho que é mais justo 
		BF_insertions[i] = user_pseud[i]*f*c
		Y_array[i] = bf_formula(BF_insertions[i])


	real_pseud = np.zeros(len(x_ticks))
	for i in range(len(x_ticks)):
		real_pseud[i] = max(user_pseud[i]/3,pseudos)

	print(" - Haas interval : ", time_interval, " \npossible pseudonyms: \n", user_pseud, " \nefective requeired for work pseudonyms:\n", real_pseud) #dividi por 3 pq 8h é 1/3 de 24h por dia de trabalho

	#print("\n H BF insertions: ", BF_insertions, " \n user_pseud : ", user_pseud, " \n BF size KB: ", Y_array)

	return Y_array

def dacose_calculation(X_array_delta, pseudos, epoch,f, p):

	x_value = X_array_delta/epoch
	Y_array = np.zeros(len(X_array_delta))
	BF_insertions = np.zeros(len(X_array_delta))

	print("cla pseudos: ",  pseudos)
	print("cla *f*c: ",  f*c)

	for i in range(len(X_array_delta)):
			treeSize = math.ceil( math.log( 1/x_value[i] ,2) )		
			#print("D treeSize: ",  treeSize)
			BF_insertions[i] = treeSize*(pseudos +p)*f*c
			Y_array[i] = bf_formula(BF_insertions[i])

			#Y_array[i] = ( (BF_insertions * (math.log(1000) ))/(  math.log(2,e)*math.log(2,e)  ) ) / 8000 #bf size for FP = 0.1%. A divisao por 8000 é para passar bits para KB

	print("\n D BF insertions: ", BF_insertions, " \n BF size KB: ", Y_array)
	return Y_array


def loadFile(filename):


	MyArray = np.array([])
	with open("Data/" + filename+'.txt') as my_file:
		for line in my_file:
			value = float(line.rstrip())#/1000
		
			MyArray = np.append( MyArray , value) #mili to sec and num of op per sec

	#print(filename + " total:" + str(np.sum(MyArray)) + " MIn: " + str(MyArray.shape) )

	mean = np.mean( MyArray )

	return mean

def haas_load_x_values(file1, file2, file3, file4, file5, file6, file7, file8, file9):
	x_ticks = np.array([loadFile(file1), loadFile(file2), loadFile(file3), loadFile(file4), loadFile(file5), loadFile(file6), loadFile(file7), loadFile(file8), loadFile(file9)])
	return x_ticks

def dacose_load_x_values(file1):
	data = loadFile(file1)

	x_ticks = np.array([data,data,data,data,data,data,data,data,data])
	return x_ticks


dacose_linestyle = 'solid'
haas_linestyle = 'dashed'

haas_day_color = "royalblue"
haas_month_color = "blue"
haas_year_color = "navy"

dacose_day_color = "limegreen"
dacose_month_color = "green"
dacose_year_color = "#06470c"  #"evergreen"

M_size = 4
L_size = 1

def make_latency_lines():

	##plot latencias
	x_ticks = np.array([43200, 3600, 900, 600, 300, 60, 30, 10, 1])

	#	15min, 10min, 5min, 1min, 30s, 10s, 1s
	#y = np.array([100, 300, 600, 1300, 1800, 2000, 2500]) # 
	y = haas_load_x_values("Haas_692_day" ,"Haas_1504_day" ,"Haas_2848_day" ,"Haas_2928_day","Haas_3072_day","Haas_5760_day","Haas_7680_day","Haas_8640_day","Haas_28800_day")
	ax[0].plot(x_ticks, y, color=haas_day_color ,  linestyle=haas_linestyle, markersize=M_size, marker='o',  linewidth = L_size)


	y = haas_load_x_values("Haas_7020_month" ,"Haas_45777_month" ,"Haas_86684_month" ,"Haas_89119_month","Haas_93502_month","Haas_175316_month","Haas_233755_month","Haas_262974_month","Haas_876582_month")
	ax[0].plot(x_ticks, y, color=haas_month_color ,  linestyle=haas_linestyle, markersize=M_size, marker='o',  linewidth = L_size)


	y = haas_load_x_values("Haas_84249_year" ,"Haas_549324_year" ,"Haas_1040210_year" ,"Haas_1069430_year","Haas_1122024_year","Haas_2103796_year","Haas_2805062_year","Haas_3155695_year","Haas_10518984_year")
	ax[0].plot(x_ticks, y, color=haas_year_color ,  linestyle=haas_linestyle, markersize=M_size, marker='o',  linewidth = L_size)


	y = dacose_load_x_values("Dacose_692_day" )
	ax[0].plot(x_ticks, y, color=dacose_day_color ,  linestyle=dacose_linestyle, markersize=M_size, marker='s',  linewidth = L_size)


	y = dacose_load_x_values("Dacose_5677_month" )
	ax[0].plot(x_ticks, y, color=dacose_month_color ,  linestyle=dacose_linestyle, markersize=M_size, marker='s',  linewidth = L_size)

	y = dacose_load_x_values("Dacose_32142_year" )
	ax[0].plot(x_ticks, y, color=dacose_year_color ,  linestyle=dacose_linestyle, markersize=M_size, marker='s',  linewidth = L_size)


def plot_lines(min_pseudo_requeired, pseudos, time_interval, f, p, period, haas_color, dacose_color):



	#	60min, 15min, 10min, 5min, 1min, 30s, 10s, 1s
	x_ticks = np.array([43200, 3600, 900, 600, 300, 60, 30, 10, 1])
	#x = np.linspace(1, 900, 5000) #1min -> 0.001
	y = haas_calculation(x_ticks, min_pseudo_requeired, time_interval,f, p,pseudos)

	#print(y)

	# Plot the data
	ax[1].plot(x_ticks, y, color=haas_color ,  linestyle=haas_linestyle, markersize=M_size,  linewidth = L_size)


#	y = haas_calculation(x_ticks, min_pseudo_requeired, time_interval,f, p)
	ax[1].plot(x_ticks, y, color=haas_color , linestyle='None',  marker='o', markersize=M_size,  linewidth = L_size)
	ax[1].plot(x_ticks[0], y[0], color=haas_color , label='Haas et al. e='+ period, linestyle=haas_linestyle,  marker='o', markersize=M_size,  linewidth = L_size)



	y = dacose_calculation(x_ticks, pseudos, time_interval,f, p)
	# Plot the data
	ax[1].plot(x_ticks, y, color=dacose_color ,  linestyle=dacose_linestyle, markersize=M_size,  linewidth = L_size)
	
	y = dacose_calculation(x_ticks, pseudos, time_interval,f, p)	
	ax[1].plot(x_ticks, y, color=dacose_color , linestyle='None',  marker='s', markersize=M_size,  linewidth = L_size)
	ax[1].plot(x_ticks[0], y[0], color=dacose_color , label='EDGAR e='+ period, linestyle=dacose_linestyle,  marker='s', markersize=M_size,  linewidth = L_size)

	#print(x_ticks)
	#print(y)
	#print("devia de confirmar que estou a fazer as contas certas \n")


#plt.axvline(x=60,linewidth=4, color="sandybrown", alpha=0.7)
ax[0].axvline(60,linewidth=4, color="sandybrown", alpha=0.7)
ax[1].axvline(60,linewidth=4, color="sandybrown", alpha=0.7)


#min_pseudo_requeired = np.array([75, 50, 25, 12, 8, 3 ,1])
min_pseudo_requeired = np.array([346, 188, 89, 61, 32, 12, 8, 3 ,1])


day = 86400 #in seconds
month = 2629746 
year = 31556952

p = 0 #um pseudonym extra, mudei pq 1 em cada 1000 da fP (https://hur.st/bloomfilter/?n=35871537&p=%200.001&m=&k=)

#podia tbm fazer o *23 e *23*12 mas acho que faz sentido para mim e nao faz para o haas, pq basta ser preciso uma vez 5 pseudonyms em 15s que se aplica igual para tudo
pseudonyms_d = 692
pseudonyms_m = 5677
pseudonyms_y = 32142

f= 0.1 # 0.0025 é 1 em vez de f/(12*23) que fica abaixo de 1

plot_lines(min_pseudo_requeired, pseudonyms_d, day, 0.0025, p, "day", haas_day_color, dacose_day_color)
plot_lines(min_pseudo_requeired, pseudonyms_m, month, f/(12), 5,"month",haas_month_color, dacose_month_color)
plot_lines(min_pseudo_requeired, pseudonyms_y, year, f, 32,"year",haas_year_color, dacose_year_color)




make_latency_lines()

#best_heuristic_result_global:  10.63789909869918 best_user_id_global:  20000280 P = 1146




#plt.xlabel("$\delta$ = unlinkability interval")
plt.xlabel("$\delta$ = slot granularity")

ax[0].set_ylabel("Client latency\nfor pseudonyms\nrenovation (ms)")
ax[1].set_ylabel("Bloom Filter size (Kb)\nfor a False Positive = 0.1%")

ax[1].invert_xaxis()
ax[0].invert_xaxis()
ax[1].set_xscale('log')
ax[0].set_yscale('log')
ax[0].set_xscale('log')
ax[1].set_yscale('log')


ax[0].label_outer()

x_ticks = np.array([43200, 3600, 900, 600, 300, 60, 30, 10, 1])
y = np.asarray([ "12h", "1h", "15m","10m","5m","1m","30s", "10s", "1s"])
#plt.xticks(x_ticks, y)
ax[1].set_xticks(x_ticks)
ax[0].set_xticks(x_ticks)
ax[1].set_xticklabels( y)



degrees = -45
plt.xticks(rotation=degrees)

L = 6
W = 1.2
ax[0].tick_params(which='major',  length=L, width=W, direction='out', axis='x')
ax[1].tick_params(which='major',  length=L, width=W, direction='out', axis='x')



# Add a legend
#plt.legend(loc=2)
#plt.legend(loc=2,ncol=3, bbox_to_anchor=(-0.1,2.5),  frameon=False)
plt.legend(loc=2,ncol=3, bbox_to_anchor=(-0.1,2.43),  frameon=False)
ax[1].xaxis.set_label_coords(0.5, -0.30)


plt.savefig("figure9.pdf", bbox_inches='tight')

# Show the plot
#plt.show()


































































