
library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity acorn_stateUpdate8 is
generic( 
        STATE_SIZE  : integer := 293; 
        M_SIZE      : integer := 8);
    port(
        s_in 		: in  std_logic_vector(STATE_SIZE  -1 downto 0);
        m_in        : in  std_logic_vector(M_SIZE      -1 downto 0);
        ca          : in  std_logic_vector(M_SIZE      -1 downto 0);
        cb          : in  std_logic_vector(M_SIZE      -1 downto 0);
        is_decrypt  : in  std_logic; 
        
        s_out      	: out std_logic_vector(STATE_SIZE  -1 downto 0);
        ks_out      : out std_logic_vector(M_SIZE      -1 downto 0)
    );
end acorn_stateUpdate8;

architecture behavior of acorn_stateUpdate8 is
    --signal t_289, t_230, t_193, t_154, t_107, t_61       :  std_logic_vector(M_SIZE     -1 downto 0); 
    signal t_289, t_230, t_193, t_154, t_107, t_61       : std_logic_vector(M_SIZE     -1 downto 0);
    
    signal ks, f                                         : std_logic_vector(M_SIZE     -1 downto 0);
    signal word_235                                      : std_logic_vector(M_SIZE     -1 downto 0); 
    signal word_196                                      : std_logic_vector(M_SIZE     -1 downto 0); 
    signal word_160                                      : std_logic_vector(M_SIZE     -1 downto 0); 
    signal word_111                                      : std_logic_vector(M_SIZE     -1 downto 0);
    signal word_66                                       : std_logic_vector(M_SIZE     -1 downto 0); 
    signal word_23                                       : std_logic_vector(M_SIZE     -1 downto 0); 
    signal word_244                                      : std_logic_vector(M_SIZE     -1 downto 0); 
    signal word_12                                       : std_logic_vector(M_SIZE     -1 downto 0);  
    signal maj1, ch1                                     : std_logic_vector(M_SIZE     -1 downto 0); 
    signal msg                                           : std_logic_vector(M_SIZE     -1 downto 0);  

begin
    word_235 <= s_in(242 downto 235);
    word_196 <= s_in(203 downto 196); 
    word_160 <= s_in(167 downto 160); 
    word_111 <= s_in(118 downto 111); 
    word_66  <= s_in(73  downto 66 ); 
    word_23  <= s_in(30  downto 23 ); 
    word_244 <= s_in(251 downto 244); 
    word_12  <= s_in(19  downto 12 ); 

    t_289 <= (x"0" & s_in(292 downto 289)) xor word_235 xor s_in(237 downto 230); 
    t_230 <= s_in(237 downto 230) xor word_196 xor s_in(200 downto 193); 
    t_193 <= s_in(200 downto 193) xor word_160 xor s_in(161 downto 154); 
    t_154 <= s_in(161 downto 154) xor word_111 xor s_in(114 downto 107); 
    t_107 <= s_in(114 downto 107) xor word_66  xor s_in(68  downto 61 ); 
    t_61  <= s_in(68  downto 61 ) xor word_23  xor s_in(7   downto 0  ); 

    ks    <= word_12 xor t_154 xor (( word_235 and t_61) xor (word_235 and t_193) xor (t_61 and t_193)); 
    maj1  <= (word_244 and word_23) xor (word_244 and word_160) xor (word_23 and word_160) ; 
    ch1   <= (t_230 and word_111) xor ((not t_230) and word_66); 
    f     <= s_in(7 downto 0) xor (not t_107) xor maj1 xor ch1 xor (ca and word_196) xor (cb and ks); 
    msg   <= ks xor m_in when is_decrypt = '1' else 
             m_in; 
    s_out  <= (f(7 downto 4) xor msg(7 downto 4)) & (t_289 xor (f(3 downto 0) & "0000") xor (msg(3 downto 0) & "0000")) & s_in(288 downto 238) & t_230 & 
             s_in(229 downto 201) & t_193 & s_in(192 downto 162) & t_154 & s_in(153 downto 115) & t_107
             & s_in(106 downto 69) & t_61 & s_in(60 downto 8); 
    ks_out <= ks xor m_in; 

end behavior;