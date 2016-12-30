-------------------------------------------------------------------------------
--! @file       PostProcessor.vhd
--! @brief      Post-processing unit for ACORN128 8-bit version.
--! @author     Tao Huang 
--! @license    This project is released under the GNU Public License.
--!             The license and distribution terms for this file may be
--!             found in the file LICENSE in this distribution or at
--!             http://www.gnu.org/licenses/gpl-3.0.txt
--! @note       Modified based on the template written by Ekawat (ice) Homsirikamol
-------------------------------------------------------------------------------

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;
use work.AEAD_pkg.all;

entity PostProcessor is
    generic (
        --! I/O size (bits)
        G_W                 : integer := 8;    --! Public data input
        G_SW                : integer := 8;    --! Secret data input
        --! Reset behavior
        G_ASYNC_RSTN        : boolean := False; --! Async active low reset
        --! Special features activation
        G_CIPH_EXP          : boolean := False; --! Ciphertext expansion
        G_REVERSE_CIPH      : boolean := False; --! Reversed ciphertext
        G_MERGE_TAG         : boolean := False; --! Merge tag with data segment
        --! Block size (bits)
        G_DBLK_SIZE         : integer := 8;   --! Data
        G_TAG_SIZE          : integer := 128;   --! Key
        --! The number of bits required to hold block size expressed in
        --! bytes = log2_ceil(G_DBLK_SIZE/8)
        G_LBS_BYTES         : integer := 4
    );
    port (
        --! Global ports
        clk                 : in  std_logic;
        rst                 : in  std_logic;
        --! Data out ports
        do_data             : out std_logic_vector(G_W          -1 downto 0);
        do_ready            : in  std_logic;
        do_valid            : out std_logic;
        --! Header ports
        cmd                 : in  std_logic_vector(24           -1 downto 0);
        cmd_valid           : in  std_logic;
        cmd_ready           : out std_logic;
        --! CipherCore
        bdo                 : in  std_logic_vector(G_DBLK_SIZE  -1 downto 0);
        bdo_valid           : in  std_logic;
        bdo_ready           : out std_logic;
        --bdo_size            : in  std_logic_vector(G_LBS_BYTES+1-1 downto 0);
        msg_auth_done       : in  std_logic;
        msg_auth_valid      : in  std_logic
    );
end PostProcessor;

architecture structure of PostProcessor is
    constant IS_BUFFER      : boolean := not (G_W = G_DBLK_SIZE);       -- false   
    constant WB             : integer := G_W/8; --! Word bytes 
    constant LOG2_WB        : integer := log2_ceil(WB);  -- 0
    constant CNT_DWORDS     : integer := (G_DBLK_SIZE+(G_W-1))/G_W;
    constant ZEROS          : std_logic_vector(G_W      -1 downto 0)
        := (others => '0');
   --! Control
    signal en_len           : std_logic;
    signal en_s             : std_logic;
    signal ld_tag           : std_logic;
    signal ld_stat          : std_logic;
    signal ld_sgmt_info     : std_logic;
    signal sel_last         : std_logic;
    signal sel_do           : std_logic;    -- output header
    signal set_first        : std_logic;
    signal clr_first        : std_logic;
    --! Status
    signal is_decrypt       : std_logic;
    signal cpl_tag          : std_logic;        --! Completed tag header
    signal cpl_stat         : std_logic;        --! Completed status header
    signal sgmt_type        : std_logic_vector(4                -1 downto 0);
    signal sgmt_len         : std_logic_vector(16               -1 downto 0); 
    
    signal sgmt_partial     : std_logic;
    signal sgmt_eot         : std_logic;
    signal sgmt_eoi         : std_logic;
    --! =======================================================================
    --! Datapath'
    --!     Signals
    signal word_size        : std_logic_vector(LOG2_WB          -1 downto 0);
    signal out_word         : std_logic_vector(G_W              -1 downto 0);
    signal out_hdr          : std_logic_vector(G_W              -1 downto 0);
    signal is_eoi           : std_logic;
    signal sel_hdr0         : std_logic; 
    signal sel_hdr1         : std_logic; 
    signal sel_hdr2         : std_logic; 
    --!     Registers
    signal msg_auth_done_r  : std_logic;
    signal msg_auth_valid_r : std_logic;
    signal reg_bdo          : std_logic_vector(G_DBLK_SIZE      -1 downto 0);
    signal reg_bdo_ready    : std_logic;
    --! =======================================================================
    --! aliases
    --!     Signal
    signal cmd_instr_opcode : std_logic_vector(4                -1 downto 0);
    signal cmd_sgmt_type    : std_logic_vector(4                -1 downto 0);
    signal cmd_sgmt_partial : std_logic;
    signal cmd_sgmt_eot     : std_logic;
    signal cmd_sgmt_eoi     : std_logic;
    signal cmd_sgmt_len     : std_logic_vector(16               -1 downto 0);
    --!     Global
    signal cmd_rdy          : std_logic;
    signal do_vld           : std_logic;
    signal bdo_rdy          : std_logic;
    --! =======================================================================
    type t_state is (S_WAIT_INSTR, S_WAIT_HDR, S_PREP, S_OUT_HDR0, S_OUT_HDR1, S_OUT_HDR2,
        S_OUT, S_GEN_TAG_HDR, S_GEN_STAT_HDR, S_WAIT_BDO, S_WAIT_BDO_CIPH);
    signal cs   : t_state;  --! Current state
    signal ns   : t_state;  --! Next state
begin
    --! =======================================================================
    --! Datapath registers and control status registers
    --! =======================================================================
    process(clk)
    begin
        if rising_edge(clk) then
            if (cs = S_WAIT_INSTR) then
                is_decrypt <= cmd_instr_opcode(0);
            end if;

            if (cs = S_WAIT_INSTR) then
                cpl_tag <= '0';
            elsif (ld_tag = '1') then
                cpl_tag <= '1';
            end if;

            if (cs = S_WAIT_INSTR) then
                cpl_stat <= '0';
            elsif (ld_stat = '1') then
                cpl_stat <= '1';
            end if;

            if (cs = S_WAIT_INSTR) then
                msg_auth_done_r <= '0';
            elsif (msg_auth_done = '1') then
                msg_auth_done_r <= '1';
                msg_auth_valid_r <= msg_auth_valid;
            end if;

            if (ld_sgmt_info = '1') then
                sgmt_type(3 downto 2) <= cmd_sgmt_type(3 downto 2);
                sgmt_type(1 downto 0) <= '0' & not is_decrypt;
                sgmt_partial  <= cmd_sgmt_partial;
                sgmt_len      <= cmd_sgmt_len;
                sgmt_eot      <= cmd_sgmt_eot;
                sgmt_eoi      <= cmd_sgmt_eoi;
            elsif (ld_tag = '1') then
                sgmt_type     <= ST_TAG;
                sgmt_partial  <= '0';
                sgmt_eot      <= '1';
                sgmt_eoi      <= '1';
                sgmt_len      <= x"0010"; 
                
            elsif (ld_stat = '1') then
                sgmt_type     <= STAT_SUCCESS(3 downto 1)
                                 & (not msg_auth_valid_r and is_decrypt);
                sgmt_partial  <= '0';
                sgmt_eot      <= '0';
                sgmt_eoi      <= '0';
                sgmt_len      <= (others => '0');
            elsif (en_len = '1') then
                if (sel_last = '1') then
                    sgmt_len <= (others => '0');
                else
                    sgmt_len <= std_logic_vector(unsigned(sgmt_len)-WB);
                end if;
            end if;

            if (bdo_rdy = '1' and bdo_valid = '1') then
                reg_bdo <= bdo;
            end if;
        end if;
    end process;

    --! Combinational logic of datapath
    
    word_size        <= sgmt_len(LOG2_WB-1 downto 0);
    sel_last <= '1' when (unsigned(sgmt_len) < WB) else '0';

    is_eoi <= '1' when (is_decrypt = '1'
                        and sgmt_type(3 downto 1) /= ST_NSEC
                        and sgmt_eot = '1')
                    or (is_decrypt = '0' and sgmt_type = ST_TAG)
                  else '0';
   
    out_hdr <= (sgmt_type & sgmt_partial & '0' & sgmt_eot & is_eoi) when sel_hdr0 = '1' else 
                x"00"                                               when sel_hdr1 = '1' else 
                sgmt_len(15 downto 8)                               when sel_hdr2 = '1' else 
                sgmt_len(7  downto 0); 

        
    do_data <= out_hdr when sel_do = '1' else bdo;

    --! Output communication
    cmd_ready <= cmd_rdy;
    gOutNotBuffer:
    bdo_ready <= bdo_rdy;
    do_valid  <= do_vld;

    --! Command FIFO dissection
    cmd_instr_opcode <= cmd(24-1 downto 24-4);
    cmd_sgmt_type    <= cmd(24-1 downto 24-4);
    cmd_sgmt_partial <= '0';

    cmd_sgmt_eot <= cmd(24-7);
    cmd_sgmt_eoi <= cmd(24-8);
    cmd_sgmt_len <= cmd(24-9 downto 24-24);


    --! =======================================================================
    --! Control
    --! =======================================================================
    --! State transition
    gNotAsync:
    if (not G_ASYNC_RSTN) generate
        process(clk)
        begin
            if rising_edge(clk) then
                if (rst = '1') then
                    cs <= S_WAIT_INSTR;
                    reg_bdo_ready <= '0';
                else
                    if (en_s = '1') then
                        cs <= ns;
                    end if;

                    --! BDO ready register
                    if (en_s = '1'
                        and (ns = S_WAIT_BDO 
                            or (G_CIPH_EXP and ns = S_WAIT_BDO_CIPH)))
                    then
                        reg_bdo_ready <= '1';
                    elsif (bdo_valid = '1' and reg_bdo_ready = '1') then
                        reg_bdo_ready <= '0';
                    end if;
                end if;
            end if;
        end process;
    end generate;

    --! Combinational logic
    gPdiComb:
    process(cs, cmd_instr_opcode,
        sgmt_type, cmd_sgmt_eot, cmd_sgmt_eoi, cmd_sgmt_len,
        is_decrypt, do_ready, bdo_valid,
        cmd_valid, sgmt_len, sgmt_eoi, sgmt_eot,
        cpl_tag, cpl_stat, msg_auth_done_r)
    begin
        ns           <= cs;
        cmd_rdy      <= '0';
        bdo_rdy      <= '0';
        do_vld       <= '0';
        en_len       <= '0';
        en_s         <= '0';
        ld_sgmt_info <= '0';
        ld_stat      <= '0';
        ld_tag       <= '0';
        sel_do       <= '0';
        sel_hdr0     <= '0';
        sel_hdr1     <= '0';
        sel_hdr2     <= '0';

        case cs is
            when S_WAIT_INSTR =>
                ns      <= S_WAIT_HDR;
                cmd_rdy <= '1';
                if (cmd_valid = '1'
                    and cmd_instr_opcode(3 downto 1) = OP_ENCDEC)
                then
                    en_s <= '1';
                end if;

            when S_WAIT_HDR =>
                ld_sgmt_info <= '1';
                cmd_rdy      <= '1';
                ns           <= S_PREP;
                if (cmd_valid = '1') then
                    en_s   <= '1';
                end if;

            --! Prepare appropriate flags and generate output header/status
            when S_PREP =>
                do_vld   <= '1';
                sel_do   <= '1';
                sel_hdr0 <= '1'; 
                
                if (do_ready = '1') then
                    en_s <= '1'; 
                    if (cpl_stat = '1') then
                        ns <= S_WAIT_INSTR;
                    else 
                        ns <= S_OUT_HDR0;     
                    end if; 
                end if; 

            when S_OUT_HDR0 => 
                do_vld   <= '1'; 
                sel_do   <= '1'; 
                sel_hdr1 <= '1'; 
                ns       <= S_OUT_HDR1; 
                if (do_ready = '1') then 
                    en_s <= '1'; 
                end if; 

            when S_OUT_HDR1 => 
                do_vld   <= '1'; 
                sel_do   <= '1'; 
                sel_hdr2 <= '1'; 
                ns       <= S_OUT_HDR2; 
                if (do_ready = '1') then 
                    en_s <= '1'; 
                end if; 

            when S_OUT_HDR2 => 
                do_vld   <= '1'; 
                sel_do   <= '1'; 
                if (do_ready = '1') then
                    if (cpl_stat = '1') then
                        ns <= S_WAIT_INSTR;
                    else
                        if (unsigned(sgmt_len) > 0)
                        then
                            ns <= S_OUT;
                        else
                            if (sgmt_eot = '1'
                                and sgmt_type(3 downto 2) = ST_D)
                            then
                                if (is_decrypt = '0') then
                                    ns <= S_GEN_TAG_HDR;
                                else
                                    ns <= S_GEN_STAT_HDR;
                                end if;
                            end if;
                        end if;
                    end if;
                    en_s   <= '1';
                    en_len <= '1';
                end if;

            --! Output data
            when S_OUT =>
                if (not IS_BUFFER) then
                    bdo_rdy <= '1';
                    if (do_ready = '1' and bdo_valid = '1') then
                        do_vld <= '1';
                        en_len <= '1';
                        en_s   <= '1';
                    end if;
                end if;

                if (unsigned(sgmt_len) = 0) then
                    if (sgmt_eot = '1') then
                        if (is_decrypt = '0' and cpl_tag = '0') then
                            ns <= S_GEN_TAG_HDR;
                        else
                            ns <= S_GEN_STAT_HDR;
                        end if;
                    else
                        ns <= S_WAIT_HDR;
                    end if;
                end if;

            when S_GEN_TAG_HDR =>
                ld_tag  <= '1';
                ns      <= S_PREP;
                en_s    <= '1';

            when S_GEN_STAT_HDR =>
                ld_stat <= '1';
                ns      <= S_PREP;
                if (is_decrypt = '0' or msg_auth_done_r = '1') then
                    en_s    <= '1';
                end if;

            when S_WAIT_BDO =>
                ns      <= S_OUT;
                bdo_rdy <= '1';
               -- ld_ctr  <= '1';
                if (bdo_valid = '1') then
                    en_s <= '1';
                end if;

            when S_WAIT_BDO_CIPH =>
                ns              <= S_PREP;
                --ld_ciph_exp_len <= '1';
                bdo_rdy         <= '1';
               -- ld_ctr          <= '1';
                if (bdo_valid = '1') then
                    en_s <= '1';
                end if;

        end case;
    end process;
end structure;
