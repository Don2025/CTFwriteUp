from libnum import *
from math import isqrt

c = 7922547866857761459807491502654216283012776177789511549350672958101810281348402284098310147796549430689253803510994877420135537268549410652654479620858691324110367182025648788407041599943091386227543182157746202947099572389676084392706406084307657000104665696654409155006313203957292885743791715198781974205578654792123191584957665293208390453748369182333152809882312453359706147808198922916762773721726681588977103877454119043744889164529383188077499194932909643918696646876907327364751380953182517883134591810800848971719184808713694342985458103006676013451912221080252735948993692674899399826084848622145815461035
z = 32115748677623209667471622872185275070257924766015020072805267359839059393284316595882933372289732127274076434587519333300142473010344694803885168557548801202495933226215437763329280242113556524498457559562872900811602056944423967403777623306961880757613246328729616643032628964072931272085866928045973799374711846825157781056965164178505232524245809179235607571567174228822561697888645968559343608375331988097157145264357626738141646556353500994924115875748198318036296898604097000938272195903056733565880150540275369239637793975923329598716003350308259321436752579291000355560431542229699759955141152914708362494482
n = 15310745161336895413406690009324766200789179248896951942047235448901612351128459309145825547569298479821101249094161867207686537607047447968708758990950136380924747359052570549594098569970632854351825950729752563502284849263730127586382522703959893392329333760927637353052250274195821469023401443841395096410231843592101426591882573405934188675124326997277775238287928403743324297705151732524641213516306585297722190780088180705070359469719869343939106529204798285957516860774384001892777525916167743272419958572055332232056095979448155082465977781482598371994798871917514767508394730447974770329967681767625495394441
e = 65537
p_add_q = isqrt(z+2*n)
p_subtr_q = isqrt(z-2*n)
p = (p_add_q+p_subtr_q)//2
q = p_add_q-p
# print(p, q)
# p = 144564833334456076455156647979862690498796694770100520405218930055633597500009574663803955456004439398699669751249623406199542605271188909145969364476344963078599240058180033000440459281558347909876143313940657252737586803051935392596519226965519859474501391969755712097119163926672753588797180811711004203301 
# q = 105909195259921349656664570904199242969110902804477734660927330311460997899731622163728968380757294196277263615386525795293086103142131020215128282050307177125962302515483190468569376643751587606016315185736245896434947691528567696271911398179288329609207435393579332931583829355558784305002360873458907029141
d = invmod(e, (p-1)*(q-1))
m = pow(c, d, n)
flag = n2s(m).decode()
print(flag) # BJD{Advanced_mathematics_is_too_hard!!!}