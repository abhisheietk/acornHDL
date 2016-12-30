-------------------------------------------------------------------------------
--! @file       PreProcessor.vhd
--! @brief      Pre-processing unit for ACORN128 8-bit version.
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

entity PreProcessor is
    generic (
        --! I/O size (bits)
        G_W                 : integer := 8;    --! Public data input
        G_SW                : integer := 8;    --! Secret data input
        --! Reset behavior
        G_ASYNC_RSTN        : boolean := False; --! Async active low reset
        --! Special features activation
        G_ENABLE_PAD        : boolean := False; --! Enable padding
        G_CIPH_EXP          : boolean := False; --! Ciphertext expansion
        G_REVERSE_CIPH      : boolean := False; --! Reversed ciphertext
        G_MERGE_TAG         : boolean := False; --! Merge tag with data segment
        --! Block size (bits)
        G_ABLK_SIZE         : integer := 8;   --! Associated data
        G_DBLK_SIZE         : integer := 8;   --! Data
        G_KEY_SIZE          : integer := 128;   --! Key
        --! The number of bits required to hold block size expressed in
        G_LBS_BYTES         : integer := 1;
        --! Padding options
        G_PAD_STYLE         : integer := 0;     --! Pad style
        G_PAD_AD            : integer := 1;     --! Padding behavior for AD
        G_PAD_D             : integer := 1      --! Padding behavior for Data
    );
    port (
        --! Global ports
        clk                 : in  std_logic;
        rst                 : in  std_logic;
        --! Publica data ports
        pdi_data            : in  std_logic_vector(G_W          -1 downto 0);
        pdi_valid           : in  std_logic;
        pdi_ready           : out std_logic;
        --! Secret data ports
        sdi_data            : in  std_logic_vector(G_SW         -1 downto 0);
        sdi_valid           : in  std_logic;
        sdi_ready           : out std_logic;
        --! CipherCore
        --!     Key
        key                 : out std_logic_vector(G_SW   -1 downto 0);
        key_ready           : in  std_logic;
        key_r_ready         : in  std_logic; -- add to indicate the load of each byte 
        key_valid           : out std_logic;
        key_update          : out std_logic;
        --!     BDI
        bdi                 : out std_logic_vector(G_DBLK_SIZE  -1 downto 0);
        decrypt             : out std_logic;
        bdi_ready           : in  std_logic;
        bdi_valid           : out std_logic;
        bdi_type            : out std_logic_vector(3            -1 downto 0);
        bdi_eot             : out std_logic;
        bdi_eoi             : out std_logic;
        --! CMD FIFO
        cmd                 : out std_logic_vector(24           -1 downto 0);
        cmd_ready           : in  std_logic;
        cmd_valid           : out std_logic
        );
end entity PreProcessor;

architecture structure of PreProcessor is
    constant DSIZE          : integer := G_DBLK_SIZE; -- 8
    constant ASIZE          : integer := G_ABLK_SIZE; -- 8
    constant WB             : integer := G_W/8; --! Word bytes: 1
    constant LOG2_WB        : integer := log2_ceil(WB); -- 0
    constant LOG2_KEYBYTES  : integer := log2_ceil(512/8); -- 8??
    constant CNT_AWORDS     : integer := (G_ABLK_SIZE+(G_W-1))/G_W; -- 1
    constant CNT_DWORDS     : integer := (G_DBLK_SIZE+(G_W-1))/G_W; -- 1
    constant CNT_KWORDS     : integer := (G_KEY_SIZE+(G_SW-1))/G_SW; -- 16 
    constant A_EQ_D         : boolean := (DSIZE = ASIZE); -- true
    constant P_IS_BUFFER    : boolean := not (G_W = DSIZE); -- false 
    constant S_IS_BUFFER    : boolean := false; -- not buffer sdi 

    --! Control status registers
    --!     Public
    signal sgmt_type        : std_logic_vector(4                -1 downto 0);
    signal sgmt_pt          : std_logic;
    signal sgmt_eoi         : std_logic;
    signal sgmt_eot         : std_logic;
    signal sgmt_lst         : std_logic;
    signal sgmt_len         : std_logic_vector(16                -1 downto 0);
    signal is_decrypt       : std_logic;
    --!     Secret
    signal reg_key_update   : std_logic;
    signal reg_key_valid    : std_logic;
    --! =======================================================================
    --! Control signals
    signal sel_pad          : std_logic;
    signal en_len           : std_logic;
    signal reg_sel_zero     : std_logic;
    --!     Public
    signal pdi_rdy          : std_logic;
    signal bdi_vld          : std_logic;
    signal set_key_upd      : std_logic;
    signal ld_sgmt_info     : std_logic;
    signal ld_ctr           : std_logic;
    signal en_ctr           : std_logic;
    signal en_ps            : std_logic;
    signal en_data          : std_logic;
    signal ctr              : std_logic_vector
        (3 downto 0);
    signal ld_plen          : std_logic; 
    
    --!     Secret
    signal sdi_rdy          : std_logic;
    signal ld_ctr2          : std_logic;
    signal en_ctr2          : std_logic;
    signal en_ss            : std_logic;
    signal en_key           : std_logic;
    signal ctr2             : std_logic_vector(3 downto 0);
    --!     Cmd
    signal wr_cmd           : std_logic;
    --! =======================================================================
    --! State
    type t_ps is (S_WAIT_INSTR, S_INSTR_LAT_KEY, S_INSTR_LAT_HDR, S_WAIT_HDR, S_READ_HDR_0, S_READ_HDR_1, 
                  S_READ_HDR_2, S_PREP, S_DATA, S_WAIT_READY);
    type t_ss is (S_WAIT_INSTR, S_INSTR_LAT_HDR, S_WAIT_HDR, S_READ_HDR, S_DATA, S_WAIT_READY);
    signal ps               : t_ps; --! Public State
    signal nps              : t_ps; --! Next Public State
    signal ss               : t_ss; --! Next Secret State
    signal nss              : t_ss; --! Next Secret State
    --! =======================================================================
    --! Data padding
    signal word_size        : std_logic_vector(LOG2_WB          -1 downto 0);
    signal data             : std_logic_vector(G_W              -1 downto 0);
    --!     Incoming data word
    signal pdata            : std_logic_vector(G_W              -1 downto 0);

    --!     Status
    signal reg_bdi_valid    : std_logic;
    --! =======================================================================
    --! Signal aliases
    signal p_instr_opcode   : std_logic_vector(4                -1 downto 0);
    signal p_sgmt_type      : std_logic_vector(4                -1 downto 0);
    signal p_sgmt_pt        : std_logic;
    signal p_sgmt_eoi       : std_logic;
    signal p_sgmt_eot       : std_logic;
    signal p_sgmt_lst       : std_logic;
    signal s_instr_opcode   : std_logic_vector(4                -1 downto 0);
    signal s_sgmt_type      : std_logic_vector(4                -1 downto 0);
    signal s_sgmt_eot       : std_logic;
    signal s_sgmt_lst       : std_logic;
begin
    --! =======================================================================
    --! Datapath (Core)
    --! =======================================================================
    data    <= pdi_data when reg_sel_zero = '0' else (others => '0');
    pdata <= data;

    --! =======================================================================
    --! Registers with rst for controller and datapath
    --! =======================================================================
    gSyncRst:
    if (not G_ASYNC_RSTN) generate
        process(clk)
        begin
            if rising_edge(clk) then
                if (rst = '1') then
                    --! Datapath
                    reg_bdi_valid  <= '0'; 
                    reg_key_update <= '0'; 
                    reg_key_valid  <= '0'; 
                    --! Control 
                    ps             <= S_WAIT_INSTR;
                    ss             <= S_WAIT_INSTR;
                else

                    --! BDI valid register
                    if (en_ps = '1' and nps = S_WAIT_READY) then
                        reg_bdi_valid <= '1';
                    elsif (reg_bdi_valid = '1' and bdi_ready = '1') then
                        reg_bdi_valid <= '0';
                    end if;
                    --! Key update register
                    if (set_key_upd = '1') then
                        reg_key_update <= '1';
                    elsif (key_ready = '1'
                            and (sdi_valid = '1'))
                    then
                        reg_key_update <= '0';
                    end if;
                    --! Key valid register
                    if (en_ss = '1' and nss = S_WAIT_READY) then
                        reg_key_valid <= '1';
                    elsif (key_ready = '1' and reg_key_valid = '1') then
                        reg_key_valid <= '0';
                    end if;
                    --! Control

                    if (en_ps = '1') then
                        ps <= nps;
                    end if;
                    if (en_ss = '1') then
                        ss <= nss;
                    end if;
                end if;
            end if;
        end process;
    end generate;

    --! =======================================================================
    --! Datapath (Output)
    --! =======================================================================
    pdi_ready <= pdi_rdy;
    sdi_ready <= sdi_rdy;
    --!     Public
    decrypt     <= is_decrypt;
    gDsizeEq:
    if (not P_IS_BUFFER) generate
        bdi             <= pdata;
        bdi_vld         <= pdi_valid when (ps = S_DATA) else '0';
        bdi_type        <= sgmt_type(3 downto 1);
        gNotCiph:
        if (not G_CIPH_EXP) generate
            bdi_eot         <= sgmt_eot
                when (ps = S_DATA and unsigned(sgmt_len) = 0)
                else '0';
            bdi_eoi         <= sgmt_eoi
                when (ps = S_DATA and unsigned(sgmt_len) = 0)
                else '0';
        end generate;
    end generate;
    
    bdi_valid       <= bdi_vld;

    gTsizeNeq:
    if (not S_IS_BUFFER) generate
        key_valid   <= sdi_valid when (ss = S_DATA) else '0';
        key         <= sdi_data;
    end generate;
    key_update  <= reg_key_update;
    --!     CMD FIFO
    cmd       <= sgmt_type & sgmt_pt & '0' 
                 & sgmt_eot & sgmt_lst
                 & sgmt_len(15 downto 8) & pdi_data when (ps = S_READ_HDR_2) else 
                 pdi_data(G_W-1 downto G_W-5) & '0'
                 & pdi_data(G_W-7 downto G_W-8)
                 & sgmt_len;
    cmd_valid <= wr_cmd;


    --! =======================================================================
    --! Control
    --! =======================================================================
    process(clk)
    begin
        if rising_edge(clk) then
            --! Operation register
            if (ps = S_WAIT_INSTR) then
                is_decrypt <= p_instr_opcode(0);
            end if;
            --! Length register
            if (ld_sgmt_info = '1') then
                sgmt_type <= pdi_data(G_W-1 downto G_W-4);
                sgmt_pt   <= pdi_data(G_W-5);
                sgmt_eoi  <= pdi_data(G_W-6);
                sgmt_eot  <= pdi_data(G_W-7);
                sgmt_lst  <= pdi_data(G_W-8);
            end if;

            if (ld_plen = '1') then 
                sgmt_len <= (sgmt_len(7 downto 0) & pdi_data); 
            elsif (en_len  = '1') and (unsigned(sgmt_len) > 0) then
                sgmt_len <= std_logic_vector(unsigned(sgmt_len)-WB);
            end if; 

            if (ld_sgmt_info = '1')
                or (P_IS_BUFFER and not A_EQ_D
                    and bdi_ready = '1' and unsigned(sgmt_len) > 0)
            then
                reg_sel_zero <= '0';
            elsif  (unsigned(sgmt_len) = 0 and en_len = '1')
            then
                reg_sel_zero <= '1';
            end if;

            --! Public data input counter register
            if (ld_ctr = '1') then
                ctr <= (others => '0');
            elsif (en_ctr = '1') then
                ctr <= std_logic_vector(unsigned(ctr) + 1);
            end if;
            --! Secret data input counter register
            if (ld_ctr2 = '1') then
                ctr2 <= (others => '0');
            elsif (en_ctr2 = '1') then
                ctr2 <= std_logic_vector(unsigned(ctr2) + 1);
            end if;
        end if;
    end process;

    sel_pad <= '1' when (unsigned(sgmt_len) < WB) else '0';

    word_size      <= sgmt_len(LOG2_WB-1 downto 0);
    --! HDR Dissection
    p_instr_opcode <= pdi_data(G_W-1 downto G_W-4);
    p_sgmt_type    <= pdi_data(G_W-1 downto G_W-4);
    p_sgmt_pt      <= pdi_data(G_W-5);
    p_sgmt_eoi     <= pdi_data(G_W-6);
    p_sgmt_eot     <= pdi_data(G_W-7);
    p_sgmt_lst     <= pdi_data(G_W-8);
    s_instr_opcode <= sdi_data(G_SW-1 downto G_SW-4);
    s_sgmt_type    <= sdi_data(G_SW-1 downto G_SW-4);
    s_sgmt_eot     <= sdi_data(G_SW-7);
    s_sgmt_lst     <= sdi_data(G_SW-8);

    gPdiComb:
    process(ps, p_instr_opcode, pdi_valid,
        sgmt_len, sgmt_type, sgmt_eot, sgmt_lst,
        p_sgmt_eot, p_sgmt_type,
        bdi_ready, cmd_ready, reg_sel_zero,
        ctr)
    begin
        nps          <= ps;
        pdi_rdy      <= '1';
        set_key_upd  <= '0';

        ld_sgmt_info <= '0';
        ld_ctr       <= '0';
        en_data      <= '0';
        en_ps        <= '0';
        en_len       <= '0';
        en_ctr       <= '0';
        ld_plen      <= '0'; 
        --en_zero      <= '0';
        wr_cmd       <= '0';

        case ps is
            when S_WAIT_INSTR =>
                ld_ctr      <= '1';
                if (p_instr_opcode(3 downto 1) = OP_ENCDEC) then
                    wr_cmd <= '1'; 
                    nps      <= S_INSTR_LAT_HDR;
                end if;
                if (p_instr_opcode = OP_ACTKEY) then
                    wr_cmd <= '1'; 
                    set_key_upd <= '1';
                    nps      <= S_INSTR_LAT_KEY; 
                end if;
                if (cmd_ready = '0') then
                    pdi_rdy <= '0';
                end if;
                if (pdi_valid = '1') then
                    en_ps  <= '1';
                end if;

            when S_INSTR_LAT_KEY => 
                en_ps <= '1'; 
                nps   <= S_WAIT_INSTR; 

            when S_INSTR_LAT_HDR =>     --! wait reading one byte for msgID
                en_ps  <= '1'; 
                nps <= S_WAIT_HDR; 

            when S_WAIT_HDR =>
                ld_sgmt_info <= '1';
                nps          <= S_READ_HDR_0;
                en_ps  <= '1'; 

            when S_READ_HDR_0 => 
                if (cmd_ready = '0') then
                    pdi_rdy <= '0';
                end if;
                if (pdi_valid = '1' and cmd_ready = '1') then
                    en_ps  <= '1';
                end if;
                nps <= S_READ_HDR_1; 

            when S_READ_HDR_1 => 
                ld_plen <= '1'; 
                en_ps  <= '1'; 
                nps <= S_READ_HDR_2; 
                
            when S_READ_HDR_2 => 
                ld_plen <= '1'; 
                en_ps  <= '1'; 
                if (sgmt_type(3 downto 2) = ST_D)
                then
                    wr_cmd <= '1';
                end if;
                nps <= S_PREP; 

            when S_PREP =>
                pdi_rdy <= '0';
                --! state transition
                if (unsigned(sgmt_len) = 0) then
                    if (sgmt_lst = '1') then
                        nps <= S_WAIT_INSTR;
                    else
                        nps <= S_WAIT_HDR;
                    end if;
                else
                    nps    <= S_DATA;
                end if;
                en_len <= '1';
                en_ps  <= '1';

            when S_DATA =>
                if (reg_sel_zero = '1'
                    or (pdi_valid = '0' or bdi_ready = '0'))
                then
                    pdi_rdy <= '0';
                end if;

                if (unsigned(sgmt_len) = 0) then
                    if (sgmt_lst = '1') then
                        nps <= S_WAIT_INSTR;
                    else
                        nps <= S_WAIT_HDR;
                    end if;
                end if;
                
                if (reg_sel_zero = '1'
                    or (pdi_valid = '1'
                        and ((not P_IS_BUFFER and bdi_ready = '1'))))
                then
                    en_len <= '1';
                    en_ps <= '1';
                end if; 
                
            when S_WAIT_READY =>
                pdi_rdy <= '0';
                ld_ctr  <= '1';
                if (unsigned(sgmt_len) = 0) then
                    if (sgmt_lst = '1') then
                        nps <= S_WAIT_INSTR;
                    else
                        nps <= S_WAIT_HDR;
                    end if;
                else
                    nps     <= S_DATA;
                end if;
                if (bdi_ready = '1') then
                    en_len  <= '1';
                    en_ps   <= '1';
                end if;
            when others => 
                null;
        end case;
    end process;

    gSdiComb:
    process(ss, s_instr_opcode, sdi_valid, ctr2, key_r_ready, key_ready)
    begin
        nss         <= ss;
        sdi_rdy     <= '0';
        en_key      <= '0';
        ld_ctr2     <= '0';
        en_ctr2     <= '0';
        en_ss       <= '0';

        case ss is
            when S_WAIT_INSTR =>
                ld_ctr2     <= '1';
                sdi_rdy     <= '1';
                if (s_instr_opcode = OP_LDKEY) then
                    nss     <= S_INSTR_LAT_HDR;
                end if;
                if (sdi_valid = '1') then
                    en_ss <= '1';
                end if;

            when S_INSTR_LAT_HDR => 
                sdi_rdy <= '1';
                en_ss   <= '1'; 
                nss <= S_WAIT_HDR; 

            when S_WAIT_HDR =>
                nss <= S_READ_HDR;
                sdi_rdy     <= '1';
                if (sdi_valid = '1') then
                    en_ss <= '1';
                end if;

            when S_READ_HDR =>      --! read remaining bytes of HDR 
                sdi_rdy <= '1';
                en_ctr2 <= '1'; 
                en_ss   <= '1'; 
                if  (unsigned(ctr2) = 2) then 
                    ld_ctr2 <= '1'; 
                    nss <= S_DATA; 
                end if;

            when S_DATA =>
                if (sdi_valid = '1' and key_r_ready = '1')
                then
                    sdi_rdy <= '1';
                    en_ctr2 <= '1'; --  inc counter only when one byte key is loaded 
                    en_ss   <= '1'; 
                end if;

                if (unsigned(ctr2) = 15) then   --! finished read key bytes 
                    nss <= S_WAIT_INSTR;
                end if;
                
            when others => 
                null; 

        end case;
    end process;
end architecture structure;
